"""The deadline and incident Searches, as `module` Search runners (`req-fedramp-20x-vdr-deadlines`, `-incidents`).

Both read every open evaluation of one scheme and compute on read: no deadline, overdue flag or effective factor is stored.
An evaluation is *open* when the finding it evaluates is open. Reads go through `tap_grid.gryphon.read_scope` with the
caller's `db_alias`; neither runner writes.

`vdr-deadlines` takes a ``view`` and returns one row per evaluation in it. The deadline is the v0 *bound*
(`req-fedramp-20x-vdr-effective`): it counts from the finding's `first_detected_at` for every evaluation, evaluated or not, and
applies the worst-case remediation row (the class, N5, `lev_irv`), so it is never later than the exact deadline. A finding whose
`first_detected_at` is null has no deadline; it appears only in ``detection_unobserved``.

`vdr-incidents` takes a ``view`` of ``internet_reachable`` (VER-TFR-IRI) or ``non_internet_reachable`` (VER-TFR-NRI). A factor
counts as set only when `backed_factors` says evidence backs it; an unsupported value reads as unset, so it cannot take an
evaluation out of a Search. In v0 PAIN cannot be backed, so it always reads as N5. The test is applied inside the one runner, so
a page never has to show two Searches to get the right answer (`req-fedramp-20x-vdr-incidents-6`).

The class is the input ``fedramp_class`` (default ``d``) and every row says it was assumed.

``max_results`` (1 to 5000, default 1000) bounds the answer and not the work: every open evaluation of the scheme is read and
computed before the rows are cut, as in `vdr-reach`, and what was left out is reported in ``warnings`` and ``info.total_rows``.
The deadline views are ordered earliest deadline first, so the cut drops the least urgent rows; ``now`` is the comparison
instant and exists so a result can be reproduced, so a page should not bind it.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from tap_plugin.compliance_core.models.compliance_finding import ComplianceFinding

from tap_grid.gryphon import read_scope
from tap_grid.models import Search

from ..deadlines import acceptance_hours, deadline_hours, evaluation_hours
from ..evaluations import EVALUATES_EDGE, backed_factors
from ..levels import COLUMN_LEV_IRV, LEVELS
from ..models.vdr_evaluation import VdrEvaluation

WORST_PAIN = LEVELS[-1]
DEADLINE_VIEWS = (
    "evaluation_overdue",
    "remediation_due",
    "remediation_overdue",
    "acceptance_reached",
    "evaluated",
    "detection_unobserved",
)
INCIDENT_VIEWS = ("internet_reachable", "non_internet_reachable")
DEFAULT_MAX_RESULTS = 1000
MAX_RESULTS = 5000

_COMMON: dict[str, Any] = {
    "fedramp_class": {"type": "string", "enum": ["a", "b", "c", "d"], "default": "d", "description": "Assumed system class."},
    "scheme": {"type": "string", "minLength": 1, "default": "max", "description": "Evaluation scheme to read."},
    "max_results": {"type": "integer", "minimum": 1, "maximum": MAX_RESULTS, "default": DEFAULT_MAX_RESULTS},
}
_ENTITY: dict[str, Any] = {"type": "string", "minLength": 1, "description": "Only this finding's evaluation."}
DEADLINES_INPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "entity_id": _ENTITY,
        "view": {"type": "string", "enum": list(DEADLINE_VIEWS), "default": "remediation_due"},
        "now": {"type": "string", "format": "date-time", "description": "The instant to compare with; default is the present."},
        **_COMMON,
    },
}
INCIDENTS_INPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "view": {"type": "string", "enum": list(INCIDENT_VIEWS), "default": "internet_reachable"},
        "entity_id": _ENTITY,
        **_COMMON,
    },
}


def _inputs(schema: dict[str, Any], inputs: dict[str, Any]) -> dict[str, Any]:
    props = schema["properties"]
    unknown = sorted(set(inputs) - set(props))
    if unknown:
        raise ValueError(f"unknown input {', '.join(unknown)}")
    merged = {key: sub["default"] for key, sub in props.items() if "default" in sub}
    merged.update({k: v for k, v in inputs.items() if v is not None})
    if merged["view"] not in props["view"]["enum"]:
        raise ValueError(f"view must be one of {', '.join(props['view']['enum'])}")
    if merged["fedramp_class"] not in props["fedramp_class"]["enum"]:
        raise ValueError(f"fedramp_class must be one of {', '.join(props['fedramp_class']['enum'])}")
    if not isinstance(merged["scheme"], str) or not merged["scheme"]:
        raise ValueError("scheme must be a non-empty string")
    if merged.get("entity_id") is not None and (not isinstance(merged["entity_id"], str) or not merged["entity_id"]):
        raise ValueError("entity_id must be a non-empty string")
    limit = merged["max_results"]
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_RESULTS:
        raise ValueError(f"max_results must be an integer from 1 to {MAX_RESULTS}")
    return merged


def _now(value: Any) -> datetime:
    if value is None:
        return datetime.now(UTC)
    if not isinstance(value, str):
        raise ValueError("now must be an ISO 8601 date-time string")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        raise ValueError("now must be an ISO 8601 date-time string") from None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _open_evaluations(scheme: str, *, db_alias: str, finding_id: str | None = None) -> list[dict[str, Any]]:
    """Every live evaluation of the scheme whose finding is open (only `finding_id`'s when given), ordered by finding key."""
    scope = read_scope.DEFAULT_SCOPE
    evaluations = {
        str(row.entity_id): row
        for row in read_scope.node_relation(scope, VdrEvaluation, db_alias=db_alias).filter(scheme=scheme)
    }
    if not evaluations:
        return []
    finding_of: dict[str, str] = {}
    for evaluation, finding in (
        read_scope.edge_relation(scope, db_alias=db_alias)
        .filter(edge_type=EVALUATES_EDGE, from_entity_id__in=sorted(evaluations))
        .values_list("from_entity_id", "to_entity_id")
    ):
        if finding_id is None or str(finding) == finding_id:
            finding_of[str(evaluation)] = str(finding)
    findings = {
        str(row.entity_id): row
        for row in read_scope.node_relation(scope, ComplianceFinding, db_alias=db_alias).filter(
            entity_id__in=sorted(set(finding_of.values())), status="open"
        )
    }
    out = []
    for evaluation_id, finding_id in finding_of.items():
        finding = findings.get(finding_id)
        if finding is None:
            continue
        out.append({"id": evaluation_id, "row": evaluations[evaluation_id], "finding_id": finding_id, "finding": finding})
    return sorted(out, key=lambda e: (e["row"].finding_source, e["row"].finding_source_key, e["id"]))


def _factors_set(row: VdrEvaluation) -> list[str]:
    return [name for name in ("likely_exploitable", "internet_reachable", "pain") if getattr(row, name) is not None]


def _base(e: dict[str, Any], p: dict[str, Any]) -> dict[str, Any]:
    detected = e["finding"].first_detected_at
    return {
        "evaluation_id": e["id"],
        "finding_id": e["finding_id"],
        "finding_source": e["row"].finding_source,
        "finding_source_key": e["row"].finding_source_key,
        "scheme": p["scheme"],
        "fedramp_class": p["fedramp_class"],
        "class_source": "assumed",
        "first_detected_at": detected.isoformat() if detected else None,
    }


def _envelope(everything: list[dict[str, Any]], limit: int) -> dict[str, Any]:
    rows = everything[:limit]
    warnings: dict[str, Any] = {}
    if len(everything) > len(rows):
        warnings["rows_omitted"] = [f"{len(everything) - len(rows)} of {len(everything)} rows were left out; max_results is {limit}"]
    return {
        "nodes": [],
        "edges": [],
        "rows": rows,
        "info": {"row_count": len(rows), "total_rows": len(everything)},
        "warnings": warnings,
    }


def vdr_deadlines(search: Search, inputs: dict[str, Any], *, db_alias: str, layer: str = "full") -> dict[str, Any]:
    """One row per open evaluation in the view, each with the v0 bound: `hours`, `due_at`, `remaining_hours`, `overdue`.

    Every row says `bound: true` and `anchor: first_detected_at`; `complete` is false in v0 because PAIN cannot be set, so
    no evaluation is complete and a timestamp alone never completes one.

    req-fedramp-20x-vdr-deadlines-1
    """
    p = _inputs(DEADLINES_INPUT_SCHEMA, inputs)
    now = _now(p.get("now"))
    view = p["view"]
    remediation = deadline_hours(p["fedramp_class"], WORST_PAIN, COLUMN_LEV_IRV, db_alias=db_alias)
    evaluation = evaluation_hours(p["fedramp_class"], db_alias=db_alias)
    acceptance = acceptance_hours(db_alias=db_alias)
    hours_for = {
        "evaluation_overdue": evaluation,
        "remediation_due": remediation,
        "remediation_overdue": remediation,
        "acceptance_reached": acceptance,
        "evaluated": remediation,
    }
    rows: list[dict[str, Any]] = []
    for e in _open_evaluations(p["scheme"], db_alias=db_alias, finding_id=p.get("entity_id")):
        row = _base(e, p)
        detected = e["finding"].first_detected_at
        if view == "detection_unobserved":
            if detected is None:
                rows.append({**row, "hours": None, "due_at": None, "remaining_hours": None, "overdue": None})
            continue
        if detected is None:
            continue  # no deadline is computed or defaulted for it
        factors = _factors_set(e["row"])
        if view == "evaluated" and not factors:
            continue
        hours = hours_for[view]
        due = detected + timedelta(hours=hours)
        remaining = (due - now).total_seconds() / 3600
        overdue = due < now
        if view in ("evaluation_overdue", "remediation_overdue", "acceptance_reached") and not overdue:
            continue
        rows.append(
            {
                **row,
                "view": view,
                "anchor": "first_detected_at",
                "bound": True,
                "complete": False,
                "factors_set": factors,
                "hours": hours,
                "due_at": due.isoformat(),
                "remaining_hours": round(remaining, 2),
                "overdue": overdue,
            }
        )
    rows.sort(key=lambda r: (r["due_at"] is None, r["due_at"] or ""))  # earliest deadline first; a stable sort keeps key order
    return _envelope(rows, p["max_results"])


#: VER-TFR-IRI is a SHOULD for classes C and D, VER-TFR-NRI for class D; a MAY otherwise.
_SHOULD = {"VER-TFR-IRI": {"c", "d"}, "VER-TFR-NRI": {"d"}}


def vdr_incidents(search: Search, inputs: dict[str, Any], *, db_alias: str, layer: str = "full") -> dict[str, Any]:
    """One row per open evaluation that is a reportable incident under the rule of the view.

    Row: the evaluation and finding, `rule`, `modal` (`SHOULD` or `MAY` for the class), the effective `likely_exploitable`,
    `internet_reachable` and `pain` (`N5`, assumed), and `unsupported`, the factors whose set value no evidence backs.

    req-fedramp-20x-vdr-incidents-6
    """
    p = _inputs(INCIDENTS_INPUT_SCHEMA, inputs)
    rule = "VER-TFR-IRI" if p["view"] == "internet_reachable" else "VER-TFR-NRI"
    modal = "SHOULD" if p["fedramp_class"] in _SHOULD[rule] else "MAY"
    evaluations = _open_evaluations(p["scheme"], db_alias=db_alias, finding_id=p.get("entity_id"))
    backed = backed_factors([e["finding_id"] for e in evaluations], scheme=p["scheme"], db_alias=db_alias)
    rows: list[dict[str, Any]] = []
    for e in evaluations:
        got = backed[e["finding_id"]]
        likely = got["likely_exploitable"] is not False
        reachable = got["internet_reachable"] is not False
        if not likely or reachable != (rule == "VER-TFR-IRI"):
            continue
        rows.append(
            {
                **_base(e, p),
                "rule": rule,
                "modal": modal,
                "likely_exploitable": likely,
                "internet_reachable": reachable,
                "pain": WORST_PAIN,
                "pain_source": "assumed",
                "unsupported": [
                    name
                    for name in ("likely_exploitable", "internet_reachable")
                    if getattr(e["row"], name) is not None and got[name] is None
                ],
            }
        )
    return _envelope(rows, p["max_results"])


SUMMARY_VIEWS = ("counts", "by_view")
SUMMARY_INPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "view": {"type": "string", "enum": list(SUMMARY_VIEWS), "default": "counts"},
        "now": DEADLINES_INPUT_SCHEMA["properties"]["now"],
        "fedramp_class": _COMMON["fedramp_class"],
        "scheme": _COMMON["scheme"],
    },
}
_SUMMARY_LABELS = (
    ("evaluations", "Open evaluations"),
    ("evaluation_overdue", "Evaluation overdue"),
    ("remediation_overdue", "Remediation overdue (worst-case bound)"),
    ("acceptance_reached", "Acceptance limit reached"),
    ("evaluated", "Evaluated (a factor set)"),
    ("detection_unobserved", "Detection time unobserved"),
    ("incidents_internet_reachable", "Reportable incidents, internet-reachable"),
    ("incidents_non_internet_reachable", "Reportable incidents, not internet-reachable"),
)


def vdr_summary(search: Search, inputs: dict[str, Any], *, db_alias: str, layer: str = "full") -> dict[str, Any]:
    """Counts of the `vdr-deadlines` and `vdr-incidents` Searches for one scheme, for cards and charts.

    `counts`: one row with `evaluations`, `evaluation_overdue`, `remediation_overdue`, `acceptance_reached`, `evaluated`,
    `detection_unobserved`, `incidents_internet_reachable` and `incidents_non_internet_reachable`. `by_view`: the same
    numbers as rows (`view`, `label`, `count`). Each count is the row total of the Search of that name, so the summary can
    never differ from the lists.

    req-fedramp-20x-vdr-summary
    """
    unknown = sorted(set(inputs) - set(SUMMARY_INPUT_SCHEMA["properties"]))
    if unknown:
        raise ValueError(f"unknown input {', '.join(unknown)}")
    view = inputs.get("view", "counts")
    if view not in SUMMARY_VIEWS:
        raise ValueError(f"view must be one of {', '.join(SUMMARY_VIEWS)}")
    shared = {k: v for k, v in inputs.items() if k in ("now", "fedramp_class", "scheme") and v is not None}
    shared["max_results"] = 1

    def total(runner: Any, which: str) -> int:
        # `now` belongs to the deadline Searches only; the incident Searches need no clock.
        given = shared if runner is vdr_deadlines else {k: v for k, v in shared.items() if k != "now"}
        return int(runner(search, {**given, "view": which}, db_alias=db_alias)["info"]["total_rows"])

    scheme = shared.get("scheme", _COMMON["scheme"]["default"])
    counts = {"evaluations": len(_open_evaluations(scheme, db_alias=db_alias))}
    for which in ("evaluation_overdue", "remediation_overdue", "acceptance_reached", "evaluated", "detection_unobserved"):
        counts[which] = total(vdr_deadlines, which)
    for which in INCIDENT_VIEWS:
        counts[f"incidents_{which}"] = total(vdr_incidents, which)
    rows = [counts] if view == "counts" else [{"view": k, "label": label, "count": counts[k]} for k, label in _SUMMARY_LABELS]
    return {"nodes": [], "edges": [], "rows": rows, "info": {"row_count": len(rows)}, "warnings": {}}
