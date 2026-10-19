"""The VDR evaluation and its two edges (`req-fedramp-20x-vdr-evaluation`, `-evidence`).

Creation through the service layer, required fields, the null convention (null = unobserved), that
`pain` cannot be set in v0, the declared natural key proved through `grift_import`, and the two edge
types: endpoint rules, required properties, the closed factor and basis lists, and the `factor`
discriminator that lets one evidence node support both factors of one evaluation.

The checks that need the evaluation's edges to read back (a factor with no evidence, a key that
disagrees with its finding) are Searches, shipped with the deadline work; they are not tested here.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
import tap_plugin.compliance_core.models as compliance  # noqa: F401 - trigger model registration
import tap_plugin.fedramp_20x_vdr.models as vdr  # noqa: F401 - trigger model registration

from tap_grid.constraints import InvalidEdgeError
from tap_grid.grift import grift_import
from tap_grid.models import Edge, Entity
from tap_grid.registry import get_model_class
from tap_grid.services import create_edge, create_node

EVALUATION = "fedramp_20x_vdr__vdr_evaluation"
FINDING = "compliance_core__compliance_finding"
EVIDENCE = "compliance_core__compliance_evidence"
EVALUATES = "EVALUATES_COMPLIANCE_FINDING__fedramp_20x_vdr"
CITES = "CITES_FACTOR_EVIDENCE__fedramp_20x_vdr"

FINDING_PAYLOAD = {"source": "github_core", "source_key": "unified-systems-com/tap#code_scanning#7", "name": "CVE-2026-1"}
EVIDENCE_PAYLOAD = {"source": "test", "source_key": "evidence-1", "name": "WAF rule blocks the payload"}
EVALUATION_PAYLOAD = {
    "finding_source": FINDING_PAYLOAD["source"],
    "finding_source_key": FINDING_PAYLOAD["source_key"],
}


def _create(type_slug: str, payload: dict[str, Any]) -> Any:
    result = create_node(type_slug, payload)
    assert result.success, f"create_node failed: {result.errors}"
    return get_model_class(type_slug).objects.get(entity=Entity.objects.get(pk=result.entity_id))


def _doc(nodes: list[dict[str, Any]], edges: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    return {
        "metadata": {"grift_version": "0"},
        "_reserved": {},
        "batches": [
            {
                "batch_entity": {
                    "entity_id": str(uuid.uuid4()),
                    "entity_type": "batch",
                    "name": "vdr evaluation test batch",
                    "dimensions": {},
                },
                "batch_node": {
                    "name": "vdr evaluation test batch",
                    "description": "",
                    "description_json": None,
                    "source": "test",
                    "metadata": {},
                },
                "nodes": nodes,
                "edges": edges or [],
            }
        ],
    }


def _ref_node(ref: str, entity_type: str, fields: dict[str, Any], name: str | None = None) -> dict[str, Any]:
    return {
        "entity": {"ref": ref, "entity_type": entity_type, "name": name or fields.get("name", ref), "dimensions": {}},
        "node": dict(fields),
    }


def _ref_edge(ref: str, from_ref: str, to_ref: str, edge_type: str, **props: Any) -> dict[str, Any]:
    return {
        "entity": {"ref": ref, "entity_type": "edge", "dimensions": {}},
        "edge": {"from_ref": from_ref, "to_ref": to_ref, "edge_type": edge_type, "properties": props},
    }


@pytest.mark.django_db
class TestNodes:
    def test_create_display_and_dimension(self) -> None:
        node = _create(EVALUATION, EVALUATION_PAYLOAD)
        node.entity.refresh_from_db()
        assert node.entity.name == f"VDR {FINDING_PAYLOAD['source_key']}"
        assert node.entity.dimensions.get("fedramp.rule") == "vdr"

    @pytest.mark.parametrize("missing", ["finding_source", "finding_source_key"])
    def test_the_finding_identity_is_required(self, missing: str) -> None:
        payload = {k: v for k, v in EVALUATION_PAYLOAD.items() if k != missing}
        assert not create_node(EVALUATION, payload).success

    def test_an_unwritten_field_is_unobserved(self) -> None:
        """req-fedramp-20x-vdr-evaluation-2: null is "no one has looked", never false, N5 or ""."""
        node = _create(EVALUATION, EVALUATION_PAYLOAD)
        for field in ("likely_exploitable", "internet_reachable", "pain", "evaluator", "evaluated_at", "rationale"):
            assert getattr(node, field) is None, field

    def test_a_written_value_round_trips(self) -> None:
        node = _create(
            EVALUATION,
            {
                **EVALUATION_PAYLOAD,
                "likely_exploitable": False,
                "internet_reachable": True,
                "evaluator": "a.reviewer",
                "evaluated_at": "2026-10-19T09:00:00+00:00",
                "rationale": "Reached only through the proxy.",
            },
        )
        assert node.likely_exploitable is False and node.internet_reachable is True
        assert node.evaluated_at.isoformat() == "2026-10-19T09:00:00+00:00"

    @pytest.mark.parametrize(
        "bad",
        [
            {"pain": "N5"},
            {"pain": "N3"},
            {"pain": "N6"},
            {"likely_exploitable": "no"},
            {"internet_reachable": 1},
            {"evaluated_at": "yesterday"},
            {"evaluator": 7},
        ],
    )
    def test_values_are_checked_and_pain_cannot_be_set(self, bad: dict[str, Any]) -> None:
        """req-fedramp-20x-vdr-evaluation-3 and -6: in v0 no non-null pain is accepted at all."""
        assert not create_node(EVALUATION, {**EVALUATION_PAYLOAD, **bad}).success

    def test_pain_null_is_accepted(self) -> None:
        assert create_node(EVALUATION, {**EVALUATION_PAYLOAD, "pain": None}).success


@pytest.mark.django_db
class TestIdentity:
    def test_two_writes_for_one_finding_are_one_node(self) -> None:
        """req-fedramp-20x-vdr-evaluation-1."""
        name = f"VDR {FINDING_PAYLOAD['source_key']}"
        ids = []
        for fields in (EVALUATION_PAYLOAD, {**EVALUATION_PAYLOAD, "likely_exploitable": False}):
            result = grift_import(_doc([_ref_node("n", EVALUATION, fields, name=name)]))
            assert result.success, result.errors
            ids.append(result.imported_batches[0].resolved_refs["n"])
        assert ids[0] == ids[1]
        assert get_model_class(EVALUATION).objects.live().count() == 1
        assert get_model_class(EVALUATION).objects.live().get().likely_exploitable is False

    def test_two_findings_are_two_evaluations(self) -> None:
        for key in ("k1", "k2"):
            fields = {**EVALUATION_PAYLOAD, "finding_source_key": key}
            assert grift_import(_doc([_ref_node("n", EVALUATION, fields, name=f"VDR {key}")])).success
        assert get_model_class(EVALUATION).objects.live().count() == 2


@pytest.mark.django_db
class TestEdges:
    def _nodes(self) -> dict[str, Any]:
        return {
            "evaluation": _create(EVALUATION, EVALUATION_PAYLOAD),
            "finding": _create(FINDING, FINDING_PAYLOAD),
            "evidence": _create(EVIDENCE, EVIDENCE_PAYLOAD),
            "other": _create("compliance_core__compliance_boundary", {"name": "boundary", "source": "t", "source_key": "b"}),
        }

    def test_an_evaluation_evaluates_a_finding_and_takes_the_dimension(self) -> None:
        n = self._nodes()
        edge = create_edge(n["evaluation"].entity, n["finding"].entity, EVALUATES)
        assert edge.entity.dimensions.get("fedramp.rule") == "vdr"

    def test_an_evaluation_cannot_evaluate_anything_but_a_finding(self) -> None:
        n = self._nodes()
        with pytest.raises(InvalidEdgeError):
            create_edge(n["evaluation"].entity, n["other"].entity, EVALUATES)

    def test_only_an_evaluation_evaluates(self) -> None:
        n = self._nodes()
        with pytest.raises(InvalidEdgeError):
            create_edge(n["evidence"].entity, n["finding"].entity, EVALUATES)

    def test_evidence_is_cited_with_a_factor_and_a_basis(self) -> None:
        """req-fedramp-20x-vdr-evidence-1."""
        n = self._nodes()
        edge = create_edge(
            n["evaluation"].entity,
            n["evidence"].entity,
            CITES,
            properties={"factor": "internet_reachable", "basis": "protected_at_perimeter", "note": "WAF"},
        )
        assert edge.properties["factor"] == "internet_reachable"
        assert edge.entity.dimensions.get("fedramp.rule") == "vdr"

    @pytest.mark.parametrize(
        "bad",
        [
            {},
            {"factor": "likely_exploitable"},
            {"basis": "code_not_present"},
            {"factor": "pain", "basis": "code_not_present"},
            {"factor": "severity", "basis": "code_not_present"},
            {"factor": "likely_exploitable", "basis": "we looked"},
            {"factor": "likely_exploitable", "basis": "code_not_present", "extra": "x"},
        ],
    )
    def test_evidence_without_a_valid_factor_and_basis_is_refused(self, bad: dict[str, Any]) -> None:
        """req-fedramp-20x-vdr-evidence-1 and -6: pain is refused until it has a basis list."""
        n = self._nodes()
        with pytest.raises(Exception, match=r"(?i)propert|schema|valid|required"):
            create_edge(n["evaluation"].entity, n["evidence"].entity, CITES, properties=bad)

    def test_evidence_cannot_be_cited_from_a_finding_through_this_edge(self) -> None:
        n = self._nodes()
        with pytest.raises(InvalidEdgeError):
            create_edge(
                n["finding"].entity,
                n["evidence"].entity,
                CITES,
                properties={"factor": "likely_exploitable", "basis": "code_not_present"},
            )

    def test_one_evidence_node_can_support_both_factors_as_two_edges(self) -> None:
        """req-fedramp-20x-vdr-evidence-2: the factor is the discriminator."""
        nodes = [
            _ref_node("e", EVALUATION, EVALUATION_PAYLOAD, name=f"VDR {FINDING_PAYLOAD['source_key']}"),
            _ref_node("v", EVIDENCE, EVIDENCE_PAYLOAD),
        ]
        both = [
            _ref_edge("c1", "e", "v", CITES, factor="likely_exploitable", basis="code_not_reachable"),
            _ref_edge("c2", "e", "v", CITES, factor="internet_reachable", basis="protected_at_perimeter"),
        ]
        assert grift_import(_doc(nodes, both)).success
        assert Edge.objects.filter(edge_type=CITES).count() == 2

    def test_citing_the_same_evidence_twice_for_one_factor_is_one_edge(self) -> None:
        nodes = [
            _ref_node("e", EVALUATION, EVALUATION_PAYLOAD, name=f"VDR {FINDING_PAYLOAD['source_key']}"),
            _ref_node("v", EVIDENCE, EVIDENCE_PAYLOAD),
        ]
        edges = [_ref_edge("c", "e", "v", CITES, factor="likely_exploitable", basis="code_not_reachable")]
        for _ in range(2):
            result = grift_import(_doc(nodes, edges))
            assert result.success, result.errors
        assert Edge.objects.filter(edge_type=CITES).count() == 1

    def test_a_resent_evaluates_edge_is_the_same_edge(self) -> None:
        nodes = [
            _ref_node("e", EVALUATION, EVALUATION_PAYLOAD, name=f"VDR {FINDING_PAYLOAD['source_key']}"),
            _ref_node("f", FINDING, FINDING_PAYLOAD),
        ]
        edges = [_ref_edge("x", "e", "f", EVALUATES)]
        for _ in range(2):
            result = grift_import(_doc(nodes, edges))
            assert result.success, result.errors
        assert Edge.objects.filter(edge_type=EVALUATES).count() == 1
