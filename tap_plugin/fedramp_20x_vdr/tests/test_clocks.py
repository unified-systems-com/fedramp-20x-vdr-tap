"""The deadline and incident Searches (`req-fedramp-20x-vdr-deadlines`, `-incidents`, `-effective-4/6/8`)."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import tap_plugin.compliance_core.models as compliance  # noqa: F401 - trigger model registration
import tap_plugin.fedramp_20x_vdr.models as vdr  # noqa: F401 - trigger model registration
from tap_plugin.fedramp_20x_vdr import deadlines
from tap_plugin.fedramp_20x_vdr.searches import clocks

from tap_grid.grift import grift_import
from tap_grid.models import Entity, Search
from tap_grid.search import execute_search
from tap_grid.services import create_edge, create_node

PACKAGE = Path(clocks.__file__).parents[1]
EVALUATION = "fedramp_20x_vdr__vdr_evaluation"
FINDING = "compliance_core__compliance_finding"
EVIDENCE = "compliance_core__compliance_evidence"
NOW = datetime(2026, 10, 21, 12, 0, tzinfo=UTC)
WHO = {"evaluator": "a.reviewer", "evaluated_at": "2026-10-20T09:00:00+00:00"}

pytestmark = pytest.mark.django_db(transaction=True, databases=["default", "search_readonly"])


@pytest.fixture(autouse=True)
def seeded() -> None:
    assert grift_import(json.loads((PACKAGE / "grift" / "timeframes.grift.json").read_text(encoding="utf-8"))).success


def _node(type_slug: str, payload: dict[str, Any]) -> Entity:
    made = create_node(type_slug, payload)
    assert made.success, made.errors
    return Entity.objects.get(pk=made.entity_id)


def make(
    key: str,
    *,
    ago: timedelta | None = timedelta(hours=1),
    status: str = "open",
    scheme: str = "max",
    backed: tuple[str, ...] = (),
    **fields: Any,
) -> Entity:
    """A finding detected `ago` before NOW and its evaluation; `backed` names the factors given evidence."""
    payload: dict[str, Any] = {"source": "t", "source_key": key, "name": key, "status": status}
    if ago is not None:
        payload["first_detected_at"] = (NOW - ago).isoformat()
    finding = _node(FINDING, payload)
    evaluation = _node(EVALUATION, {"finding_source": "t", "finding_source_key": key, "scheme": scheme, **fields})
    create_edge(evaluation, finding, "EVALUATES_COMPLIANCE_FINDING__fedramp_20x_vdr")
    for factor in backed:
        evidence = _node(EVIDENCE, {"source": "t", "source_key": f"{key}-{factor}", "name": factor, "kind": "screenshot"})
        create_edge(evaluation, evidence, "CITES_FACTOR_EVIDENCE__fedramp_20x_vdr", {"factor": factor, "basis": "code_not_reachable"})
        create_edge(finding, evidence, "CITES_COMPLIANCE_EVIDENCE__compliance_core", {"support_kind": "informational"})
    return finding


def keys(result: dict[str, Any]) -> list[str]:
    return [r["finding_source_key"] for r in result["rows"]]


def due(view: str, **inputs: Any) -> dict[str, Any]:
    return clocks.vdr_deadlines(None, {"view": view, "now": NOW.isoformat(), **inputs}, db_alias="default")  # type: ignore[arg-type]


def incidents(view: str, **inputs: Any) -> dict[str, Any]:
    return clocks.vdr_incidents(None, {"view": view, **inputs}, db_alias="default")  # type: ignore[arg-type]


class TestDeadlines:
    @pytest.mark.spec("req-fedramp-20x-vdr-deadlines-2")
    def test_class_d_remediation_is_detection_plus_twelve_hours(self) -> None:
        make("a", ago=timedelta(hours=3))
        (row,) = due("remediation_due")["rows"]
        assert (row["hours"], row["bound"], row["anchor"]) == (12, True, "first_detected_at")
        assert row["due_at"] == (NOW - timedelta(hours=3) + timedelta(hours=12)).isoformat()
        assert (row["remaining_hours"], row["overdue"]) == (9.0, False)
        assert row["class_source"] == "assumed"

    @pytest.mark.spec("req-fedramp-20x-vdr-deadlines-2")
    def test_the_class_is_an_input(self) -> None:
        make("a")
        (row,) = due("remediation_due", fedramp_class="a")["rows"]
        assert row["hours"] == deadlines.deadline_hours("a", "N5", "lev_irv")

    @pytest.mark.spec("req-fedramp-20x-vdr-deadlines-1")
    def test_overdue_is_the_due_list_past_its_deadline(self) -> None:
        make("late", ago=timedelta(hours=13))
        make("ok", ago=timedelta(hours=2))
        assert keys(due("remediation_due")) == ["late", "ok"]
        assert keys(due("remediation_overdue")) == ["late"]

    @pytest.mark.spec("req-fedramp-20x-vdr-deadlines-3")
    def test_an_unobserved_detection_time_is_listed_and_in_no_overdue_search(self) -> None:
        make("none", ago=None)
        assert keys(due("detection_unobserved")) == ["none"]
        (row,) = due("detection_unobserved")["rows"]
        assert (row["hours"], row["due_at"], row["overdue"]) == (None, None, None)
        for view in ("remediation_due", "remediation_overdue", "evaluation_overdue", "acceptance_reached", "evaluated"):
            assert keys(due(view)) == []

    @pytest.mark.spec("req-fedramp-20x-vdr-deadlines-6")
    def test_a_timestamp_alone_does_not_complete_an_evaluation(self) -> None:
        make("a", ago=timedelta(hours=49), likely_exploitable=False, internet_reachable=False, **WHO)
        (row,) = due("evaluation_overdue")["rows"]
        assert row["complete"] is False
        assert row["hours"] == deadlines.evaluation_hours("d") == 48

    @pytest.mark.spec("req-fedramp-20x-vdr-deadlines-6")
    def test_the_evaluation_deadline_is_not_overdue_before_it(self) -> None:
        make("a", ago=timedelta(hours=47))
        assert keys(due("evaluation_overdue")) == []

    @pytest.mark.spec("req-fedramp-20x-vdr-deadlines-4")
    def test_acceptance_counts_192_days_from_detection(self) -> None:
        make("old", ago=timedelta(days=193))
        make("young", ago=timedelta(days=191))
        assert deadlines.acceptance_hours() == 4608
        assert keys(due("acceptance_reached")) == ["old"]

    @pytest.mark.spec("req-fedramp-20x-vdr-deadlines-4")
    @pytest.mark.spec("req-fedramp-20x-vdr-effective-4")
    def test_setting_a_factor_never_removes_a_deadline_and_the_anchor_stays_detection(self) -> None:
        make("set", ago=timedelta(hours=13), likely_exploitable=False, **WHO)
        make("blank", ago=timedelta(hours=13))
        assert keys(due("remediation_overdue")) == ["blank", "set"]
        assert keys(due("evaluated")) == ["set"]
        (row,) = due("evaluated")["rows"]
        assert (row["bound"], row["factors_set"], row["hours"]) == (True, ["likely_exploitable"], 12)
        assert row["first_detected_at"] == (NOW - timedelta(hours=13)).isoformat()  # not evaluated_at

    @pytest.mark.spec("req-fedramp-20x-vdr-effective-8")
    def test_only_the_requested_scheme_and_only_open_findings_are_read(self) -> None:
        make("a")
        make("other", scheme="algo2")
        make("closed", status="resolved")
        assert keys(due("remediation_due")) == ["a"]
        assert keys(due("remediation_due", scheme="algo2")) == ["other"]

    @pytest.mark.spec("req-fedramp-20x-vdr-deadlines-1")
    def test_nothing_is_stored(self) -> None:
        make("a", ago=timedelta(hours=20))
        before = Entity.objects.count()
        due("remediation_overdue")
        assert Entity.objects.count() == before

    @pytest.mark.spec("req-fedramp-20x-vdr-deadlines-1")
    def test_the_most_overdue_comes_first_so_a_cut_drops_the_least_urgent(self) -> None:
        make("a-late", ago=timedelta(hours=10))
        make("z-latest", ago=timedelta(hours=40))
        make("m-mid", ago=timedelta(hours=20))
        result = due("remediation_due", max_results=2)
        assert keys(result) == ["z-latest", "m-mid"]
        assert result["info"]["total_rows"] == 3 and "rows_omitted" in result["warnings"]

    @pytest.mark.spec("req-fedramp-20x-vdr-deadlines-1")
    @pytest.mark.parametrize(
        "bad",
        [
            {"view": "nope"}, {"bogus": 1}, {"now": "yesterday"}, {"now": 5}, {"max_results": 0}, {"max_results": -1},
            {"max_results": 5001}, {"max_results": True}, {"fedramp_class": "z"}, {"scheme": ""},
        ],
    )  # fmt: skip
    def test_bad_inputs_are_refused(self, bad: dict[str, Any]) -> None:
        with pytest.raises(ValueError):  # noqa: PT011
            clocks.vdr_deadlines(None, bad, db_alias="default")  # type: ignore[arg-type]


class TestIncidents:
    @pytest.mark.spec("req-fedramp-20x-vdr-incidents-1")
    def test_an_all_null_evaluation_is_an_internet_reachable_incident_at_class_d(self) -> None:
        make("a")
        (row,) = incidents("internet_reachable")["rows"]
        assert (row["rule"], row["modal"], row["pain"], row["pain_source"]) == ("VER-TFR-IRI", "SHOULD", "N5", "assumed")
        assert (row["likely_exploitable"], row["internet_reachable"]) == (True, True)
        assert incidents("non_internet_reachable")["rows"] == []

    @pytest.mark.spec("req-fedramp-20x-vdr-incidents-3")
    @pytest.mark.parametrize(
        ("fedramp_class", "iri", "nri"),
        [("a", "MAY", "MAY"), ("b", "MAY", "MAY"), ("c", "SHOULD", "MAY"), ("d", "SHOULD", "SHOULD")],
    )
    def test_the_modal_follows_the_class(self, fedramp_class: str, iri: str, nri: str) -> None:
        make("a", internet_reachable=False, backed=("internet_reachable",), **WHO)
        make("b")
        assert incidents("internet_reachable", fedramp_class=fedramp_class)["rows"][0]["modal"] == iri
        assert incidents("non_internet_reachable", fedramp_class=fedramp_class)["rows"][0]["modal"] == nri

    @pytest.mark.spec("req-fedramp-20x-vdr-incidents-2")
    @pytest.mark.spec("req-fedramp-20x-vdr-incidents-4")
    def test_a_backed_unreachable_moves_the_finding_to_the_other_search(self) -> None:
        make("a", internet_reachable=False, backed=("internet_reachable",), **WHO)
        assert keys(incidents("internet_reachable")) == []
        (row,) = incidents("non_internet_reachable")["rows"]
        assert (row["rule"], row["internet_reachable"], row["pain"]) == ("VER-TFR-NRI", False, "N5")

    @pytest.mark.spec("req-fedramp-20x-vdr-incidents-4")
    def test_a_backed_not_likely_exploitable_leaves_both(self) -> None:
        make("a", likely_exploitable=False, backed=("likely_exploitable",), **WHO)
        make("b", likely_exploitable=False, internet_reachable=False, backed=("likely_exploitable", "internet_reachable"), **WHO)
        assert keys(incidents("internet_reachable")) == [] and keys(incidents("non_internet_reachable")) == []

    @pytest.mark.spec("req-fedramp-20x-vdr-incidents-5")
    @pytest.mark.spec("req-fedramp-20x-vdr-effective-6")
    def test_an_unsupported_false_still_reads_as_the_worst_case_and_is_reported(self) -> None:
        make("a", likely_exploitable=False, internet_reachable=False, **WHO)  # no evidence edge
        (row,) = incidents("internet_reachable")["rows"]
        assert row["unsupported"] == ["likely_exploitable", "internet_reachable"]
        assert incidents("non_internet_reachable")["rows"] == []

    @pytest.mark.spec("req-fedramp-20x-vdr-incidents-5")
    def test_only_the_factor_edge_without_the_finding_citing_it_is_unsupported(self) -> None:
        finding = make("a", internet_reachable=False, **WHO)
        evidence = _node(EVIDENCE, {"source": "t", "source_key": "e", "name": "e", "kind": "screenshot"})
        evaluation = Entity.objects.get(pk=vdr.VdrEvaluation.objects.live().get(finding_source_key="a").entity_id)
        create_edge(evaluation, evidence, "CITES_FACTOR_EVIDENCE__fedramp_20x_vdr", {"factor": "internet_reachable", "basis": "code_not_reachable"})
        assert keys(incidents("internet_reachable")) == ["a"]
        assert finding.pk

    @pytest.mark.spec("req-fedramp-20x-vdr-incidents-5")
    def test_a_backed_value_without_evaluator_or_time_is_unsupported(self) -> None:
        make("a", likely_exploitable=False, backed=("likely_exploitable",))  # no evaluator, no evaluated_at
        assert keys(incidents("internet_reachable")) == ["a"]

    @pytest.mark.spec("req-fedramp-20x-vdr-incidents-3")
    @pytest.mark.parametrize("bad", [{"max_results": 0}, {"fedramp_class": "z"}, {"view": "x"}])
    def test_bad_inputs_are_refused_not_read_as_may(self, bad: dict[str, Any]) -> None:
        with pytest.raises(ValueError):  # noqa: PT011
            clocks.vdr_incidents(None, bad, db_alias="default")  # type: ignore[arg-type]

    @pytest.mark.spec("req-fedramp-20x-vdr-effective-8")
    def test_only_the_requested_scheme_and_open_findings_are_read(self) -> None:
        make("a")
        make("other", scheme="algo2")
        make("closed", status="resolved")
        assert keys(incidents("internet_reachable")) == ["a"]
        assert keys(incidents("internet_reachable", scheme="algo2")) == ["other"]


class TestSurface:
    @pytest.mark.spec("req-fedramp-20x-vdr-deadlines-5")
    def test_the_runners_are_registered_and_run_through_the_search_service(self) -> None:
        from tap_grid.registry import get_search_runner

        assert get_search_runner("tap_plugin.fedramp_20x_vdr.searches.clocks:vdr-deadlines") is clocks.vdr_deadlines
        assert get_search_runner("tap_plugin.fedramp_20x_vdr.searches.clocks:vdr-incidents") is clocks.vdr_incidents
        make("a")
        search = Search(
            search_type="module",
            root="node",
            name="vdr-incidents",
            definition={"runner_key": "tap_plugin.fedramp_20x_vdr.searches.clocks:vdr-incidents"},
            input_schema=clocks.INCIDENTS_INPUT_SCHEMA,
        )
        assert len(execute_search(search, {})["rows"]) == 1

    @pytest.mark.spec("req-fedramp-20x-vdr-effective-8")
    def test_neither_runner_filters_on_the_scheme_dimension(self) -> None:
        text = Path(clocks.__file__).read_text(encoding="utf-8")
        assert "vdr.scheme" not in text.replace("`vdr.scheme`", "")
