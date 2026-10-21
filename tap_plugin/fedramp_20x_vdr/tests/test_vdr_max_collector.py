"""The VDR-max collector (`req-fedramp-20x-vdr-collector`), end to end through `run_collection`.

Findings are seeded through the service layer inside each test, where they roll back and can never
reach a real grid. The collector reads them through Gryphon and writes through GRIFT, so these tests
exercise both paths. They cover the definition of done (every open, vulnerability-linked finding gets an
all-null evaluation), idempotence, that an evaluation a person has written is never overwritten, and
that unlinked and resolved findings are left alone.
"""

from __future__ import annotations

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
from tap_grid.models import Edge, Entity
from tap_grid.registry import get_model_class
from tap_grid.services import create_edge, create_node

FINDING = "compliance_core__compliance_finding"
VULNERABILITY = "compliance_core__compliance_vulnerability"
EVALUATION = "fedramp_20x_vdr__vdr_evaluation"
CONCERNS = "CONCERNS_COMPLIANCE_VULNERABILITY__compliance_core"
EVALUATES = "EVALUATES_COMPLIANCE_FINDING__fedramp_20x_vdr"
FACTORS = ("likely_exploitable", "internet_reachable", "pain", "evaluator", "evaluated_at", "rationale")

pytestmark = pytest.mark.django_db(transaction=True, databases=["default", "search_readonly"])


@pytest.fixture
def isolate_collector_registry() -> Iterator[None]:
    """Snapshot and empty the collector registry for the test, restore on exit.

    The harness idiom tap_cares' own tests use, kept local because that fixture lives in tap_cares'
    test directory and is not available to a plugin's tests.
    """
    with isolated_registry(collector_registry):
        yield


def _entity(node_id: Any) -> Entity:
    return Entity.objects.get(pk=node_id)


def _vulnerability(vuln_id: str) -> Entity:
    """The one node for a public CVE id: a second finding reuses it."""
    from tap_plugin.compliance_core.models import ComplianceVulnerability

    existing = ComplianceVulnerability.objects.live().filter(vuln_id=vuln_id).first()
    if existing is not None:
        return existing.entity
    made = create_node(VULNERABILITY, {"vuln_id": vuln_id})
    assert made.success, made.errors
    return _entity(made.entity_id)


def _finding(key: str, *, status: str = "open", vulnerabilities: tuple[str, ...] = ("CVE-2026-1",)) -> str:
    """A finding, with an edge to each named vulnerability (none = an unlinked finding)."""
    made = create_node(
        FINDING, {"source": "github_core", "source_key": key, "name": f"finding {key}", "status": status}
    )
    assert made.success, made.errors
    for vuln_id in vulnerabilities:
        create_edge(_entity(made.entity_id), _vulnerability(vuln_id), CONCERNS)
    return str(made.entity_id)


def _link(finding_id: str, vuln_id: str) -> None:
    create_edge(_entity(finding_id), _vulnerability(vuln_id), CONCERNS)


def _register(key: str = "vdr-max") -> Collector:
    register_collector(
        key=key,
        cls=VdrMaxCollector,
        scope="tap_plugin.fedramp_20x_vdr.tests",
        name="VDR max fixture",
        description="fixture",
    )
    reconcile_collector_nodes()
    collector = Collector.objects.get(collector_registry=f"tap_plugin.fedramp_20x_vdr.tests:{key}")
    assert isinstance(collector, Collector)
    return collector


def _run(collector: Collector) -> Any:
    job = run_collection(collector)
    job.refresh_from_db()
    assert job.status == CollectionJobStatus.SUCCESSFUL.value, (job.summary, job.results)
    return job


def _evaluations() -> dict[str, Any]:
    return {e.finding_source_key: e for e in get_model_class(EVALUATION).objects.live()}


class TestDefinitionOfDone:
    def test_every_open_linked_finding_gets_an_all_null_evaluation(self, isolate_collector_registry: Any) -> None:
        """req-fedramp-20x-vdr-collector-1: on an empty grid, one run, one evaluation per finding."""
        for key in ("a", "b", "c"):
            _finding(key)
        job = _run(_register())
        evaluations = _evaluations()
        assert sorted(evaluations) == ["a", "b", "c"]
        for evaluation in evaluations.values():
            assert all(getattr(evaluation, f) is None for f in FACTORS), "every factor is unobserved"
            assert evaluation.finding_source == "github_core"
        assert "3 new evaluation" in job.summary

    def test_each_evaluation_is_tied_to_its_own_finding(self, isolate_collector_registry: Any) -> None:
        a = _finding("a")
        b = _finding("b", vulnerabilities=("CVE-2026-2",))
        _run(_register())
        edges = {(str(e.from_entity_id), str(e.to_entity_id)) for e in Edge.objects.filter(edge_type=EVALUATES)}
        by_finding = {str(e.to_entity_id): str(e.from_entity_id) for e in Edge.objects.filter(edge_type=EVALUATES)}
        assert len(edges) == 2
        assert by_finding[a] == str(_evaluations()["a"].entity_id)
        assert by_finding[b] == str(_evaluations()["b"].entity_id)

    def test_a_finding_with_two_vulnerabilities_gets_one_evaluation(self, isolate_collector_registry: Any) -> None:
        finding = _finding("twice", vulnerabilities=("CVE-2026-1",))
        _link(finding, "CVE-2026-9")
        _run(_register())
        assert sorted(_evaluations()) == ["twice"]
        assert Edge.objects.filter(edge_type=EVALUATES).count() == 1


class TestWhatItLeavesAlone:
    def test_unlinked_and_resolved_findings_get_no_evaluation(self, isolate_collector_registry: Any) -> None:
        """req-fedramp-20x-vdr-collector-4: no vulnerability edge, no evaluation; resolved is history."""
        _finding("linked")
        _finding("unlinked", vulnerabilities=())
        _finding("resolved", status="resolved")
        _run(_register())
        assert sorted(_evaluations()) == ["linked"]

    def test_a_finding_with_no_key_is_skipped_and_counted_not_defaulted(self, isolate_collector_registry: Any) -> None:
        keyed = _finding("keyed")
        assert keyed
        bare = create_node(FINDING, {"name": "no identity at all", "status": "open"})
        assert bare.success, bare.errors
        create_edge(_entity(bare.entity_id), _vulnerability("CVE-2026-7"), CONCERNS)
        job = _run(_register())
        assert sorted(_evaluations()) == ["keyed"]
        assert "1 skipped" in job.summary
        assert any(w.get("message_code") == "UNKEYED_FINDINGS" for w in job.results["warn"])

    def test_an_evaluation_a_person_wrote_is_never_overwritten(self, isolate_collector_registry: Any) -> None:
        """req-fedramp-20x-vdr-collector-3: the node is not re-emitted, so its fields survive."""
        mine_finding = _finding("mine")
        _finding("new")
        written = create_node(
            EVALUATION,
            {
                "finding_source": "github_core",
                "finding_source_key": "mine",
                "scheme": "max",
                "likely_exploitable": False,
                "evaluator": "a.reviewer",
                "evaluated_at": "2026-10-19T09:00:00+00:00",
                "rationale": "Only reachable through the proxy.",
            },
        )
        assert written.success, written.errors
        version_before = _entity(written.entity_id).version
        _run(_register())
        mine = _evaluations()["mine"]
        assert mine.likely_exploitable is False and mine.evaluator == "a.reviewer"
        assert mine.rationale == "Only reachable through the proxy."
        assert _entity(written.entity_id).version == version_before, "the entity was not even rewritten"
        assert sorted(_evaluations()) == ["mine", "new"]
        # It had no edge to its finding, which every Search traverses, so the run gave it the edge
        # and nothing else.
        edge = Edge.objects.get(edge_type=EVALUATES, from_entity_id=written.entity_id)
        assert str(edge.to_entity_id) == mine_finding

    def test_an_evaluation_with_no_edge_is_reconnected_and_only_with_the_edge(
        self, isolate_collector_registry: Any
    ) -> None:
        """req-fedramp-20x-vdr-collector-6: an edge-less evaluation of an in-scope finding gets its edge."""
        finding = _finding("orphan")
        orphan = create_node(
            EVALUATION,
            {"finding_source": "github_core", "finding_source_key": "orphan", "scheme": "max", "rationale": "typed by hand"},
        )
        assert orphan.success, orphan.errors
        assert not Edge.objects.filter(edge_type=EVALUATES).exists()
        collector = _register()
        job = _run(collector)
        assert "reconnected 1" in job.summary and "0 new evaluation" in job.summary
        assert [str(e.to_entity_id) for e in Edge.objects.filter(edge_type=EVALUATES)] == [finding]
        assert _evaluations()["orphan"].rationale == "typed by hand"
        assert len(_evaluations()) == 1, "no second evaluation was made"
        again = _run(collector)
        assert "No new evaluations" in again.summary, "and the next run has nothing left to do"

    def test_a_resolved_finding_keeps_its_evaluation(self, isolate_collector_registry: Any) -> None:
        _finding("will-resolve")
        collector = _register()
        _run(collector)
        from tap_plugin.compliance_core.models import ComplianceFinding

        finding = ComplianceFinding.objects.live().get(source_key="will-resolve")
        from tap_grid.services import patch_node

        assert patch_node(finding.entity_id, {"status": "resolved"}).success
        _run(collector)
        assert sorted(_evaluations()) == ["will-resolve"], "never deleted, resolved or not"


class TestIdempotence:
    def test_a_second_run_emits_nothing_and_changes_nothing(self, isolate_collector_registry: Any) -> None:
        """req-fedramp-20x-vdr-collector-2."""
        _finding("a")
        _finding("b")
        collector = _register()
        _run(collector)
        before = {k: (e.entity_id, _entity(e.entity_id).version) for k, e in _evaluations().items()}
        edges_before = Edge.objects.filter(edge_type=EVALUATES).count()
        second = _run(collector)
        after = {k: (e.entity_id, _entity(e.entity_id).version) for k, e in _evaluations().items()}
        assert before == after
        assert Edge.objects.filter(edge_type=EVALUATES).count() == edges_before == 2
        assert "No new evaluations" in second.summary

    def test_a_new_finding_is_picked_up_on_the_next_run(self, isolate_collector_registry: Any) -> None:
        _finding("old")
        collector = _register()
        _run(collector)
        _finding("later", vulnerabilities=("CVE-2026-3",))
        _run(collector)
        assert sorted(_evaluations()) == ["later", "old"]


class TestReadsThatDisagree:
    """The overwrite guard is only as good as the read behind it, so a read that looks wrong stops the run."""

    def _failing_run(self, collector: Collector) -> Any:
        job = run_collection(collector)
        job.refresh_from_db()
        assert job.status == CollectionJobStatus.FAILED.value, (job.status, job.summary)
        return job

    def test_an_existing_set_that_reads_empty_while_evaluations_are_connected_submits_nothing(
        self, isolate_collector_registry: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """req-fedramp-20x-vdr-collector-7: a connected evaluation is an evaluation, so an "existing"
        read that returns none of them is wrong, and acting on it would blank what people wrote."""
        from tap_plugin.fedramp_20x_vdr.collectors.vdr_max import collector as module

        _finding("a")
        collector = _register()
        _run(collector)
        before = {k: _entity(e.entity_id).version for k, e in _evaluations().items()}
        _finding("b", vulnerabilities=("CVE-2026-2",))

        real = module.execute_gryphon_raw

        def _flaky(query: str, inputs: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
            if query == module.EXISTING_EVALUATIONS:
                return {"nodes": [], "edges": []}  # the bare empty envelope: looks like "none exist"
            return real(query, inputs, **kwargs)

        monkeypatch.setattr(module, "execute_gryphon_raw", _flaky)
        job = self._failing_run(collector)
        assert any(e.get("message_code") == "INCONSISTENT_READ" for e in job.results["error"])
        monkeypatch.undo()
        assert sorted(_evaluations()) == ["a"], "nothing was submitted, not even the legitimate new one"
        assert {k: _entity(e.entity_id).version for k, e in _evaluations().items()} == before

    def test_a_read_that_raises_fails_the_run_and_submits_nothing(
        self, isolate_collector_registry: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from tap_plugin.fedramp_20x_vdr.collectors.vdr_max import collector as module

        _finding("a")

        def _boom(*args: Any, **kwargs: Any) -> dict[str, Any]:
            raise RuntimeError("the read failed")

        monkeypatch.setattr(module, "execute_gryphon_raw", _boom)
        self._failing_run(_register())
        monkeypatch.undo()
        assert _evaluations() == {}


class TestWriteSurface:
    def test_it_submits_one_batch_and_does_not_override_the_abort_default(
        self, isolate_collector_registry: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """req-fedramp-20x-vdr-collector-5: one GRIFT batch through submit_grift, abort-on-rejection kept."""
        _finding("a")
        calls: list[dict[str, Any]] = []
        original = VdrMaxCollector.submit_grift

        def _spy(self: Any, document: Any, **kwargs: Any) -> Any:
            calls.append({"batches": len(document["batches"]), "kwargs": kwargs})
            return original(self, document, **kwargs)

        monkeypatch.setattr(VdrMaxCollector, "submit_grift", _spy)
        _run(_register())
        assert calls == [{"batches": 1, "kwargs": {}}]
