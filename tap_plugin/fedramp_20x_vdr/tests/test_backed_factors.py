"""The evidence-backed value of a factor (`req-fedramp-20x-vdr-pain-9`, `-effective-6`, `-pain-4`)."""

from __future__ import annotations

from typing import Any

import pytest
import tap_plugin.compliance_core.models as compliance  # noqa: F401 - trigger model registration
import tap_plugin.fedramp_20x_vdr.models as vdr  # noqa: F401 - trigger model registration
from tap_plugin.fedramp_20x_vdr.evaluations import backed_factors

from tap_grid.models import Entity
from tap_grid.services import create_edge, create_node

EVALUATION = "fedramp_20x_vdr__vdr_evaluation"
FINDING = "compliance_core__compliance_finding"
EVIDENCE = "compliance_core__compliance_evidence"
EVALUATES = "EVALUATES_COMPLIANCE_FINDING__fedramp_20x_vdr"
CITES_FACTOR = "CITES_FACTOR_EVIDENCE__fedramp_20x_vdr"
CITES_FINDING = "CITES_COMPLIANCE_EVIDENCE__compliance_core"

pytestmark = pytest.mark.django_db(transaction=True, databases=["default", "search_readonly"])

WHO = {"evaluator": "a.reviewer", "evaluated_at": "2026-10-20T09:00:00+00:00"}


def _node(type_slug: str, payload: dict[str, Any]) -> Entity:
    made = create_node(type_slug, payload)
    assert made.success, made.errors
    return Entity.objects.get(pk=made.entity_id)


def _finding(key: str) -> Entity:
    return _node(FINDING, {"source": "t", "source_key": key, "name": key, "status": "open"})


def _evaluation(finding: Entity, scheme: str = "max", **fields: Any) -> Entity:
    evaluation = _node(
        EVALUATION,
        {"finding_source": "t", "finding_source_key": finding.name, "scheme": scheme, **fields},
    )
    create_edge(evaluation, finding, EVALUATES)
    return evaluation


def _evidence(key: str = "e1") -> Entity:
    return _node(EVIDENCE, {"source": "t", "source_key": key, "name": key, "kind": "screenshot"})


def _cite_factor(evaluation: Entity, evidence: Entity, factor: str) -> None:
    create_edge(evaluation, evidence, CITES_FACTOR, {"factor": factor, "basis": "code_not_reachable"})


def _both(finding: Entity) -> dict[str, bool | None]:
    return backed_factors([str(finding.pk)])[str(finding.pk)]


@pytest.mark.spec("req-fedramp-20x-vdr-pain-9")
def test_a_finding_with_no_evaluation_has_no_backed_value() -> None:
    finding = _finding("a")
    assert _both(finding) == {"likely_exploitable": None, "internet_reachable": None}


@pytest.mark.spec("req-fedramp-20x-vdr-pain-9")
def test_a_null_factor_is_none_even_with_an_evaluation() -> None:
    finding = _finding("a")
    _evaluation(finding, **WHO)
    assert _both(finding) == {"likely_exploitable": None, "internet_reachable": None}


@pytest.mark.spec("req-fedramp-20x-vdr-pain-9")
@pytest.mark.spec("req-fedramp-20x-vdr-effective-6")
def test_a_value_without_evidence_is_none() -> None:
    finding = _finding("a")
    _evaluation(finding, likely_exploitable=False, internet_reachable=False, **WHO)
    assert _both(finding) == {"likely_exploitable": None, "internet_reachable": None}


@pytest.mark.spec("req-fedramp-20x-vdr-pain-4")
@pytest.mark.parametrize("value", [True, False])
def test_a_backed_value_is_returned_as_it_is(value: bool) -> None:
    finding = _finding("a")
    evaluation = _evaluation(finding, internet_reachable=value, **WHO)
    evidence = _evidence()
    _cite_factor(evaluation, evidence, "internet_reachable")
    create_edge(finding, evidence, CITES_FINDING, {"support_kind": "informational"})
    assert _both(finding) == {"likely_exploitable": None, "internet_reachable": value}


@pytest.mark.spec("req-fedramp-20x-vdr-effective-6")
def test_the_finding_must_cite_the_same_evidence() -> None:
    finding = _finding("a")
    evaluation = _evaluation(finding, likely_exploitable=False, **WHO)
    _cite_factor(evaluation, _evidence(), "likely_exploitable")  # the finding does not cite it
    assert _both(finding)["likely_exploitable"] is None


@pytest.mark.spec("req-fedramp-20x-vdr-effective-6")
def test_the_evidence_must_be_for_that_factor() -> None:
    finding = _finding("a")
    evaluation = _evaluation(finding, likely_exploitable=False, **WHO)
    evidence = _evidence()
    _cite_factor(evaluation, evidence, "internet_reachable")  # the other factor
    create_edge(finding, evidence, CITES_FINDING, {"support_kind": "informational"})
    assert _both(finding)["likely_exploitable"] is None


@pytest.mark.spec("req-fedramp-20x-vdr-effective-6")
@pytest.mark.parametrize("missing", ["evaluator", "evaluated_at"])
def test_an_evaluation_without_a_who_or_a_when_backs_nothing(missing: str) -> None:
    finding = _finding("a")
    evaluation = _evaluation(finding, likely_exploitable=False, **{k: v for k, v in WHO.items() if k != missing})
    evidence = _evidence()
    _cite_factor(evaluation, evidence, "likely_exploitable")
    create_edge(finding, evidence, CITES_FINDING, {"support_kind": "informational"})
    assert _both(finding)["likely_exploitable"] is None


@pytest.mark.spec("req-fedramp-20x-vdr-pain-4")
def test_only_the_asked_scheme_is_read() -> None:
    finding = _finding("a")
    other = _evaluation(finding, scheme="stackarmor", internet_reachable=False, **WHO)
    evidence = _evidence()
    _cite_factor(other, evidence, "internet_reachable")
    create_edge(finding, evidence, CITES_FINDING, {"support_kind": "informational"})
    assert backed_factors([str(finding.pk)])[str(finding.pk)]["internet_reachable"] is None  # default scheme max
    assert backed_factors([str(finding.pk)], scheme="stackarmor")[str(finding.pk)]["internet_reachable"] is False


@pytest.mark.spec("req-fedramp-20x-vdr-pain-9")
def test_every_requested_finding_is_answered_and_the_effective_value_is_none_read_as_true() -> None:
    a, b = _finding("a"), _finding("b")
    got = backed_factors([str(a.pk), str(b.pk)])
    assert set(got) == {str(a.pk), str(b.pk)}
    effective = {f: (True if v is None else v) for f, v in got[str(a.pk)].items()}
    assert effective == {"likely_exploitable": True, "internet_reachable": True}


@pytest.mark.spec("req-fedramp-20x-vdr-pain-9")
def test_if_two_evaluations_of_one_scheme_disagree_the_worst_case_wins() -> None:
    finding = _finding("a")
    evidence = _evidence()
    create_edge(finding, evidence, CITES_FINDING, {"support_kind": "informational"})
    for key, value in (("a", False), ("a-second", True)):
        evaluation = _node(
            EVALUATION, {"finding_source": "t", "finding_source_key": key, "scheme": "max", "likely_exploitable": value, **WHO}
        )
        create_edge(evaluation, finding, EVALUATES)
        _cite_factor(evaluation, evidence, "likely_exploitable")
    assert _both(finding)["likely_exploitable"] is True


@pytest.mark.spec("req-fedramp-20x-vdr-pain-9")
def test_no_findings_is_an_empty_answer() -> None:
    assert backed_factors([]) == {}
