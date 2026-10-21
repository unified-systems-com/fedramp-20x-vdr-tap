"""An evaluation carries a scheme (`req-fedramp-20x-vdr-evaluation-1`, `-7`, `-9`, `-collector-8`, `-9`).

Several algorithms can evaluate one finding, each under its own scheme; the VDR-max collector writes `max` and
only ever reads and touches `max`. The scheme is a column in the natural key; the `vdr.scheme` dimension is a copy.
"""

from __future__ import annotations

import importlib
import uuid
from collections.abc import Iterator
from typing import Any

import pytest
import tap_plugin.compliance_core.models as compliance  # noqa: F401 - trigger model registration
import tap_plugin.fedramp_20x_vdr.models as vdr  # noqa: F401 - trigger model registration
from tap_plugin.fedramp_20x_vdr.collectors.vdr_max.collector import VdrMaxCollector

from tap.pytest_harness import isolated_registry
from tap_cares.models import CollectionJobStatus, Collector
from tap_cares.registry import collector_registry, reconcile_collector_nodes, register_collector
from tap_cares.services import run_collection
from tap_grid.grift import grift_import
from tap_grid.models import Edge, Entity
from tap_grid.registry import get_model_class
from tap_grid.services import create_edge, create_node

EVALUATION = "fedramp_20x_vdr__vdr_evaluation"
FINDING = "compliance_core__compliance_finding"
VULNERABILITY = "compliance_core__compliance_vulnerability"
CONCERNS = "CONCERNS_COMPLIANCE_VULNERABILITY__compliance_core"
EVALUATES = "EVALUATES_COMPLIANCE_FINDING__fedramp_20x_vdr"

pytestmark = pytest.mark.django_db(transaction=True, databases=["default", "search_readonly"])


@pytest.fixture
def isolate_collector_registry() -> Iterator[None]:
    with isolated_registry(collector_registry):
        yield


def _entity(pk: Any) -> Entity:
    return Entity.objects.get(pk=pk)


def _finding(key: str) -> Entity:
    made = create_node(FINDING, {"source": "github_core", "source_key": key, "name": f"finding {key}", "status": "open"})
    assert made.success, made.errors
    vuln = get_model_class(VULNERABILITY).objects.live().filter(vuln_id="CVE-2026-1").first()
    if vuln is None:
        made_vuln = create_node(VULNERABILITY, {"vuln_id": "CVE-2026-1"})
        assert made_vuln.success, made_vuln.errors
        vuln_entity = _entity(made_vuln.entity_id)
    else:
        vuln_entity = vuln.entity
    finding = _entity(made.entity_id)
    create_edge(finding, vuln_entity, CONCERNS)
    return finding


def _evaluation(key: str, scheme: str, **extra: Any) -> Entity:
    made = create_node(EVALUATION, {"finding_source": "github_core", "finding_source_key": key, "scheme": scheme, **extra})
    assert made.success, made.errors
    return _entity(made.entity_id)


def _collector() -> Collector:
    register_collector(
        key="vdr-max-scheme",
        cls=VdrMaxCollector,
        scope="tap_plugin.fedramp_20x_vdr.tests",
        name="VDR max scheme fixture",
        description="fixture",
    )
    reconcile_collector_nodes()
    return Collector.objects.get(collector_registry="tap_plugin.fedramp_20x_vdr.tests:vdr-max-scheme")


def _run_registered(collector: Collector) -> Any:
    job = run_collection(collector)
    job.refresh_from_db()
    assert job.status == CollectionJobStatus.SUCCESSFUL.value, (job.summary, job.results)
    return job


def _run() -> Any:
    return _run_registered(_collector())


def _all() -> list[Any]:
    return list(get_model_class(EVALUATION).objects.live().order_by("finding_source_key", "scheme"))


class TestKey:
    @pytest.mark.spec("req-fedramp-20x-vdr-evaluation-1")
    def test_the_key_is_the_finding_and_the_scheme(self) -> None:
        assert get_model_class(EVALUATION).NATURAL_KEY == ("finding_source", "finding_source_key", "scheme")

    @pytest.mark.spec("req-fedramp-20x-vdr-evaluation-1")
    def test_one_finding_can_carry_one_evaluation_per_scheme(self) -> None:
        _evaluation("f1", "max")
        _evaluation("f1", "stackarmor")
        assert [(e.finding_source_key, e.scheme) for e in _all()] == [("f1", "max"), ("f1", "stackarmor")]

    @pytest.mark.spec("req-fedramp-20x-vdr-evaluation-1")
    def test_the_same_scheme_twice_is_one_node(self) -> None:
        def doc(rationale: str) -> dict[str, Any]:
            return {
                "metadata": {"grift_version": "0"},
                "_reserved": {},
                "batches": [
                    {
                        "batch_entity": {"entity_id": str(uuid.uuid4()), "entity_type": "batch", "name": "k", "dimensions": {}},
                        "batch_node": {"name": "k", "description": "", "description_json": None, "source": "test", "metadata": {}},
                        "nodes": [
                            {
                                "entity": {"ref": "e", "entity_type": EVALUATION, "name": "VDR f1", "dimensions": {}},
                                "node": {"finding_source": "github_core", "finding_source_key": "f1", "scheme": "max", "rationale": rationale},
                            }
                        ],
                        "edges": [],
                    }
                ],
            }

        for rationale in ("first", "second"):
            result = grift_import(doc(rationale))
            assert result.success, result.errors
        assert len(_all()) == 1 and _all()[0].rationale == "second"

    @pytest.mark.spec("req-fedramp-20x-vdr-evaluation-7")
    @pytest.mark.parametrize("bad", [None, "", "x" * 65, 7, ["max"]])
    def test_scheme_is_required_free_text_of_one_to_sixty_four_characters(self, bad: Any) -> None:
        made = create_node(EVALUATION, {"finding_source": "github_core", "finding_source_key": "f1", "scheme": bad})
        assert not made.success

    @pytest.mark.spec("req-fedramp-20x-vdr-evaluation-7")
    def test_a_write_without_a_scheme_is_refused(self) -> None:
        assert not create_node(EVALUATION, {"finding_source": "github_core", "finding_source_key": "f1"}).success

    @pytest.mark.spec("req-fedramp-20x-vdr-evaluation-7")
    @pytest.mark.parametrize("scheme", ["max", "StackArmor v2", "a" * 64, "ünï-schème"])
    def test_any_name_is_accepted(self, scheme: str) -> None:
        assert create_node(EVALUATION, {"finding_source": "github_core", "finding_source_key": "f1", "scheme": scheme}).success


class TestCollector:
    @pytest.mark.spec("req-fedramp-20x-vdr-collector-8")
    def test_it_writes_scheme_max_and_stamps_node_and_edge(self, isolate_collector_registry: Any) -> None:
        _finding("a")
        _run()
        (evaluation,) = _all()
        assert evaluation.scheme == "max"
        assert _entity(evaluation.entity_id).dimensions == {"fedramp.rule": "vdr", "vdr.scheme": "max"}
        edge = Edge.objects.get(edge_type=EVALUATES, from_entity_id=evaluation.entity_id)
        assert _entity(edge.entity_id).dimensions == {"fedramp.rule": "vdr", "vdr.scheme": "max"}

    @pytest.mark.spec("req-fedramp-20x-vdr-collector-9")
    def test_another_schemes_evaluation_is_not_a_max_one_and_the_finding_still_gets_max(
        self, isolate_collector_registry: Any
    ) -> None:
        finding = _finding("a")
        other = _evaluation("a", "stackarmor", rationale="by hand", likely_exploitable=False)
        create_edge(other, finding, EVALUATES)
        _run()
        by_scheme = {e.scheme: e for e in _all()}
        assert sorted(by_scheme) == ["max", "stackarmor"]
        assert by_scheme["stackarmor"].rationale == "by hand" and by_scheme["stackarmor"].likely_exploitable is False
        assert by_scheme["max"].likely_exploitable is None

    @pytest.mark.spec("req-fedramp-20x-vdr-collector-9")
    def test_another_schemes_edge_less_evaluation_is_not_reconnected(self, isolate_collector_registry: Any) -> None:
        _finding("a")
        loose = _evaluation("a", "stackarmor")
        _run()
        assert not Edge.objects.filter(edge_type=EVALUATES, from_entity_id=loose.pk).exists()

    @pytest.mark.spec("req-fedramp-20x-vdr-collector-2")
    def test_a_second_run_changes_nothing(self, isolate_collector_registry: Any) -> None:
        _finding("a")
        collector = _collector()
        _run_registered(collector)
        before = [(e.pk, e.version) for e in Entity.objects.filter(entity_type=EVALUATION)]
        _run_registered(collector)
        assert [(e.pk, e.version) for e in Entity.objects.filter(entity_type=EVALUATION)] == before


class TestMigration:
    @pytest.mark.spec("req-fedramp-20x-vdr-evaluation-9")
    def test_existing_evaluations_and_their_edges_are_stamped_max_and_nothing_else_is(self) -> None:
        from django.apps import apps
        from django.db import connection

        finding = _finding("a")
        old = _evaluation("a", "max")
        create_edge(old, finding, EVALUATES)
        unrelated = _finding("unrelated")
        # An evaluation written before this release carries no vdr.scheme dimension.
        Entity.objects.filter(pk=old.pk).update(dimensions={"fedramp.rule": "vdr"})
        edge = Edge.objects.get(edge_type=EVALUATES, from_entity_id=old.pk)
        Entity.objects.filter(pk=edge.entity_id).update(dimensions={"fedramp.rule": "vdr"})
        unrelated_before = dict(_entity(unrelated.pk).dimensions)

        class _Editor:
            def __init__(self) -> None:
                self.connection = connection

        migration = importlib.import_module("tap_plugin.fedramp_20x_vdr.migrations.0002_evaluation_scheme")
        migration.stamp_existing_as_max(apps, _Editor())

        assert _entity(old.pk).dimensions == {"fedramp.rule": "vdr", "vdr.scheme": "max"}
        assert _entity(edge.entity_id).dimensions == {"fedramp.rule": "vdr", "vdr.scheme": "max"}
        assert _entity(unrelated.pk).dimensions == unrelated_before

    @pytest.mark.spec("req-fedramp-20x-vdr-evaluation-9")
    def test_a_conflicting_dimension_is_normalized_to_max(self) -> None:
        from django.apps import apps
        from django.db import connection

        finding = _finding("a")
        old = _evaluation("a", "max")
        create_edge(old, finding, EVALUATES)
        edge = Edge.objects.get(edge_type=EVALUATES, from_entity_id=old.pk)
        for pk in (old.pk, edge.entity_id):
            Entity.objects.filter(pk=pk).update(dimensions={"fedramp.rule": "vdr", "vdr.scheme": "other"})

        class _Editor:
            def __init__(self) -> None:
                self.connection = connection

        migration = importlib.import_module("tap_plugin.fedramp_20x_vdr.migrations.0002_evaluation_scheme")
        migration.stamp_existing_as_max(apps, _Editor())
        assert _entity(old.pk).dimensions["vdr.scheme"] == "max"
        assert _entity(edge.entity_id).dimensions["vdr.scheme"] == "max"

    @pytest.mark.spec("req-fedramp-20x-vdr-evaluation-9")
    def test_a_row_backfilled_at_the_column_only_is_found_by_the_collector(self, isolate_collector_registry: Any) -> None:
        """What AddField(default="max") does: the column changes under the row and nothing else does.

        The collector reads `e.data.scheme` through Gryphon; this shows that reads the column, so an evaluation
        written before the scheme existed is found and the collector does not add a second `max` beside it.
        """
        finding = _finding("a")
        old = _evaluation("a", "legacy-placeholder", rationale="written by a person")
        create_edge(old, finding, EVALUATES)
        get_model_class(EVALUATION).objects.filter(entity_id=old.pk).update(scheme="max")
        _run()
        evaluations = _all()
        assert [(e.finding_source_key, e.scheme) for e in evaluations] == [("a", "max")]
        assert evaluations[0].rationale == "written by a person"


class TestUpgradeFromV01:
    """The real upgrade path: a database at migration 0001 holding a v0.1.0 evaluation, migrated forward to 0002."""

    @pytest.mark.spec("req-fedramp-20x-vdr-evaluation-9")
    def test_a_v01_evaluation_becomes_max_and_the_collector_adds_no_second(self, isolate_collector_registry: Any) -> None:
        from django.db import connection
        from django.db.migrations.executor import MigrationExecutor

        app = "fedramp_20x_vdr"
        finding = _finding("old")

        executor = MigrationExecutor(connection)
        executor.migrate([(app, "0001_initial")])  # back to the released schema: no scheme column
        try:
            old_apps = MigrationExecutor(connection).loader.project_state([(app, "0001_initial")]).apps
            Historic = old_apps.get_model(app, "VdrEvaluation")
            assert "scheme" not in {f.name for f in Historic._meta.get_fields()}
            entity = Entity.objects.create(
                entity_type=EVALUATION, name="VDR old", dimensions={"fedramp.rule": "vdr"}
            )
            Historic.objects.create(
                entity_id=entity.pk,
                finding_source="github_core",
                finding_source_key="old",
                rationale="written by v0.1.0",
            )
        finally:
            MigrationExecutor(connection).migrate([(app, "0002_evaluation_scheme")])

        migrated = get_model_class(EVALUATION).objects.get(entity_id=entity.pk)
        assert migrated.scheme == "max" and migrated.rationale == "written by v0.1.0"
        assert Entity.objects.get(pk=entity.pk).dimensions == {"fedramp.rule": "vdr", "vdr.scheme": "max"}

        _run()
        evaluations = _all()
        assert [(e.finding_source_key, e.scheme) for e in evaluations] == [("old", "max")]
        assert evaluations[0].rationale == "written by v0.1.0"
        # It had no edge to its finding, so the run gave it the edge and nothing else.
        edge = Edge.objects.get(edge_type=EVALUATES, from_entity_id=entity.pk)
        assert str(edge.to_entity_id) == str(finding.pk)
