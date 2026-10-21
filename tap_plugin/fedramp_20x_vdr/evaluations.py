"""The evidence-backed value of an evaluation's factors (`req-fedramp-20x-vdr-pain-9`, `-effective-6`).

A method that lets evidence override its own signals needs to tell "no evidence" from "evidence says true", which the
effective value (an unbacked factor reads as the worst case) cannot. `backed_factors` returns, for each finding and each of
`likely_exploitable` and `internet_reachable`, `True`, `False` or `None`, where `None` means no evidence backs a value. The
effective value is that value with `None` read as `True`, so the two never disagree. If two evaluations of one scheme
point at one finding and disagree, the worst case (`True`) wins.

A factor is backed only when all three hold, the rule of `req-fedramp-20x-vdr-effective-6`: the evaluation's factor is not
null, an evidence edge for that factor runs from the evaluation, the finding also cites that evidence, and `evaluator`
and `evaluated_at` are set. Reads go through `tap_grid.gryphon.read_scope` with the caller's `db_alias`.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable

from tap_grid.gryphon import read_scope

from .models.vdr_evaluation import VdrEvaluation

EVALUATES_EDGE = "EVALUATES_COMPLIANCE_FINDING__fedramp_20x_vdr"
FACTOR_EVIDENCE_EDGE = "CITES_FACTOR_EVIDENCE__fedramp_20x_vdr"
FINDING_EVIDENCE_EDGE = "CITES_COMPLIANCE_EVIDENCE__compliance_core"
FACTORS: tuple[str, str] = ("likely_exploitable", "internet_reachable")
DEFAULT_SCHEME = "max"


def backed_factors(
    finding_ids: Iterable[str], *, scheme: str = DEFAULT_SCHEME, db_alias: str = "default"
) -> dict[str, dict[str, bool | None]]:
    """`{finding_id: {factor: True | False | None}}` for every requested finding, from evaluations of one scheme."""
    wanted = sorted({str(f) for f in finding_ids})
    out: dict[str, dict[str, bool | None]] = {f: dict.fromkeys(FACTORS) for f in wanted}
    if not wanted:
        return out
    scope = read_scope.DEFAULT_SCOPE
    edges = read_scope.edge_relation(scope, db_alias=db_alias)

    evaluated: dict[str, str] = {}  # evaluation id -> finding id
    for evaluation, finding in edges.filter(edge_type=EVALUATES_EDGE, to_entity_id__in=wanted).values_list(
        "from_entity_id", "to_entity_id"
    ):
        evaluated[str(evaluation)] = str(finding)
    if not evaluated:
        return out
    rows = {
        str(row.entity_id): row
        for row in read_scope.node_relation(scope, VdrEvaluation, db_alias=db_alias).filter(
            entity_id__in=sorted(evaluated), scheme=scheme
        )
    }
    if not rows:
        return out

    factor_evidence: dict[tuple[str, str], set[str]] = defaultdict(set)  # (evaluation, factor) -> evidence ids
    for evaluation, evidence, properties in edges.filter(
        edge_type=FACTOR_EVIDENCE_EDGE, from_entity_id__in=sorted(rows)
    ).values_list("from_entity_id", "to_entity_id", "properties"):
        factor = (properties or {}).get("factor")
        if factor in FACTORS:
            factor_evidence[(str(evaluation), factor)].add(str(evidence))
    cited_by_finding: dict[str, set[str]] = defaultdict(set)
    for finding, evidence in edges.filter(
        edge_type=FINDING_EVIDENCE_EDGE, from_entity_id__in=sorted({evaluated[e] for e in rows})
    ).values_list("from_entity_id", "to_entity_id"):
        cited_by_finding[str(finding)].add(str(evidence))

    for evaluation_id in sorted(rows):
        row = rows[evaluation_id]
        finding = evaluated[evaluation_id]
        if not row.evaluator or row.evaluated_at is None:
            continue
        for factor in FACTORS:
            value = getattr(row, factor)
            if value is None:
                continue
            if factor_evidence[(evaluation_id, factor)] & cited_by_finding[finding]:
                # A finding has one evaluation per scheme by its key; if two ever point at one finding and disagree,
                # the worst case wins, so a backed True is never hidden by a backed False.
                out[finding][factor] = bool(value) or bool(out[finding][factor])
    return out
