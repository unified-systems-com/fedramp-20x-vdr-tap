"""The coverage snapshot collector (`req-fedramp-20x-vdr-coverage-snapshot`).

The collector is a few-line subclass of compliance_core's `SearchSnapshotCollector`, so these tests check the
wiring that is this plugin's: what it records, that it is registered, that a run writes a snapshot and a missing
Search writes nothing, and that the Search id and the dependency floor are pinned. The base class's own behaviour
is tested in compliance_core.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import tap_plugin.compliance_core.models as compliance  # noqa: F401 - trigger model registration
import tap_plugin.fedramp_20x_vdr.models as vdr  # noqa: F401 - trigger model registration
from tap_plugin.compliance_core.collectors.search_snapshot import SearchSnapshotCollector
from tap_plugin.fedramp_20x_vdr.collectors.coverage_snapshot.collector import (
    COVERAGE_SUMMARY_SEARCH_ID,
    CoverageSnapshotCollector,
)

from tap.pytest_harness import isolated_registry
from tap_cares.models import CollectionJobStatus, Collector
from tap_cares.registry import collector_registry, reconcile_collector_nodes, register_collector
from tap_cares.services import run_collection
from tap_grid.models import Edge, Entity
from tap_grid.registry import get_model_class
from tap_grid.services import create_node

SNAPSHOT = "compliance_core__compliance_search_snapshot"
CAPTURES = "CAPTURES_SEARCH__compliance_core"
KEY = "tap_plugin.compliance_core.searches.dimension_mapping"
PLAYGROUND_SEED_ID = "01a15b2f-df3b-7569-bf22-9ead3f816b84"

pytestmark = pytest.mark.django_db(transaction=True, databases=["default", "search_readonly"])


@pytest.fixture
def isolate_collector_registry() -> Iterator[None]:
    with isolated_registry(collector_registry):
        yield


def _search() -> Entity:
    made = create_node(
        "search",
        {
            "name": "classification mapping summary",
            "search_type": "module",
            "root": "node",
            "definition": {"runner_key": f"{KEY}:dimension-mapping-summary"},
            "input_schema": {
                "type": "object",
                "properties": {
                    "mappings": {
                        "type": "array",
                        "default": [
                            {
                                "entity_type": "compliance_core__compliance_exception",
                                "keys": [{"key": "dataclass.action", "allowed": ["read", "none"]}],
                            }
                        ],
                    }
                },
            },
        },
    )
    assert made.success, made.errors
    return Entity.objects.get(pk=made.entity_id)


def _register_fixture(key: str = "coverage-snapshot") -> Collector:
    register_collector(
        key=key,
        cls=CoverageSnapshotCollector,
        scope="tap_plugin.fedramp_20x_vdr.tests",
        name="coverage snapshot fixture",
        description="fixture",
    )
    reconcile_collector_nodes()
    return Collector.objects.get(collector_registry=f"tap_plugin.fedramp_20x_vdr.tests:{key}")


def _snapshots() -> list[Any]:
    return list(get_model_class(SNAPSHOT).objects.live().order_by("observed_at"))


class TestSubclass:
    @pytest.mark.spec("req-fedramp-20x-vdr-coverage-snapshot-1")
    def test_it_is_a_subclass_that_sets_two_attributes_and_defines_no_run(self) -> None:
        assert issubclass(CoverageSnapshotCollector, SearchSnapshotCollector)
        assert CoverageSnapshotCollector.SOURCE == "fedramp_20x_vdr"
        assert CoverageSnapshotCollector.SEARCH_ENTITY_IDS == (COVERAGE_SUMMARY_SEARCH_ID,)
        assert "run" not in vars(CoverageSnapshotCollector)

    @pytest.mark.spec("req-fedramp-20x-vdr-coverage-snapshot-5")
    def test_the_search_id_is_the_literal_the_playground_seed_uses(self) -> None:
        """One-sided on purpose: it shows a change made here. The playground pins the same literal in its tests."""
        assert COVERAGE_SUMMARY_SEARCH_ID == PLAYGROUND_SEED_ID


class TestRegistered:
    @pytest.mark.spec("req-fedramp-20x-vdr-coverage-snapshot-2")
    def test_it_is_registered_under_the_plugin_scope_and_reconciles_to_one_collector_node(self) -> None:
        reconcile_collector_nodes()
        nodes = Collector.objects.filter(collector_registry="fedramp_20x_vdr:coverage_snapshot")
        assert nodes.count() == 1
        node = nodes.get()
        assert node.name and node.description
        reconcile_collector_nodes()
        assert Collector.objects.filter(collector_registry="fedramp_20x_vdr:coverage_snapshot").count() == 1


class TestRun:
    @pytest.mark.spec("req-fedramp-20x-vdr-coverage-snapshot-3")
    def test_one_run_writes_one_snapshot_and_a_second_run_a_second(
        self, isolate_collector_registry: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        search = _search()
        monkeypatch.setattr(CoverageSnapshotCollector, "SEARCH_ENTITY_IDS", (str(search.pk),))
        collector = _register_fixture()
        for expected in (1, 2):
            job = run_collection(collector)
            job.refresh_from_db()
            assert job.status == CollectionJobStatus.SUCCESSFUL.value, (job.summary, job.results)
            assert len(_snapshots()) == expected
        snap = _snapshots()[0]
        assert snap.source == "fedramp_20x_vdr" and snap.search_name == "classification mapping summary"
        edges = Edge.objects.filter(edge_type=CAPTURES, from_entity_id=snap.entity_id)
        assert [str(e.to_entity_id) for e in edges] == [str(search.pk)]

    @pytest.mark.spec("req-fedramp-20x-vdr-coverage-snapshot-4")
    def test_a_grid_without_the_search_fails_the_run_naming_the_id_and_writes_nothing(
        self, isolate_collector_registry: Any
    ) -> None:
        job = run_collection(_register_fixture())
        job.refresh_from_db()
        assert job.status == CollectionJobStatus.FAILED.value
        assert COVERAGE_SUMMARY_SEARCH_ID in json.dumps(job.results)
        assert _snapshots() == [] and Edge.objects.filter(edge_type=CAPTURES).count() == 0


class TestFloor:
    @pytest.mark.spec("req-fedramp-20x-vdr-coverage-snapshot-6")
    def test_the_ci_record_pins_a_compliance_core_that_ships_the_base_class(self) -> None:
        record = json.loads((Path(__file__).parent.parent / "boot" / "ci.boot.json").read_text())
        pinned = next(p for p in record["install"]["plugins"] if p["slug"] == "compliance_core")["source"]["rev"]
        version = tuple(int(part) for part in pinned.removeprefix("v").split("."))
        assert version >= (0, 8, 7), f"compliance_core {pinned} predates SearchSnapshotCollector (first shipped in v0.8.7)"
