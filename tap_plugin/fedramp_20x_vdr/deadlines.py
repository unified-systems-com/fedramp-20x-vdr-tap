"""The remediation deadline, in hours, from the seeded timeframe rows (`req-fedramp-20x-vdr-pain-5`, `-6`, `-7`).

`deadline_hours` answers one question: how many hours does a class have, at a PAIN level and in an exposure column, under
VDR-TFR-PVR. It returns hours, never a date: the clock anchor belongs to the deadlines requirement. The read goes through
`tap_grid.gryphon.read_scope`, so a tombstoned row contributes nothing, with the caller's `db_alias`.
"""

from __future__ import annotations

from tap_grid.gryphon import read_scope

from .levels import COLUMNS, LEVELS, level_rank
from .models.vdr_timeframe import VdrTimeframe

RULE = "VDR-TFR-PVR"
CLASSES: tuple[str, ...] = ("a", "b", "c", "d")


def deadline_hours(fedramp_class: str, pain: str, column: str, *, db_alias: str = "default") -> int | None:
    """The hours of the `VDR-TFR-PVR` row for the class, level and column; `None` for N1, which has no timeframe.

    A value outside the classes, the levels or the columns is refused. A cell FedRAMP publishes (N2 to N5) that is not
    seeded raises `LookupError` naming it, because a missing row is a data fault, not an answer.
    """
    if fedramp_class not in CLASSES:
        raise ValueError(f"{fedramp_class!r} is not a FedRAMP class; expected one of {', '.join(CLASSES)}")
    level_rank(pain)
    if column not in COLUMNS:
        raise ValueError(f"{column!r} is not an exposure column; expected one of {', '.join(COLUMNS)}")
    if pain == LEVELS[0]:
        return None  # FedRAMP publishes no timeframe for N1 (req-fedramp-20x-vdr-low-pain)
    row = (
        read_scope.node_relation(read_scope.DEFAULT_SCOPE, VdrTimeframe, db_alias=db_alias)
        .filter(rule=RULE, fedramp_class=fedramp_class, pain=pain, exposure=column)
        .first()
    )
    if row is None:
        raise LookupError(f"no {RULE} timeframe row for class {fedramp_class}, {pain}, {column}; the seed is incomplete")
    return int(row.hours)


EVALUATION_RULE = "VER-TFR-EVU"
ACCEPTANCE_RULE = "VER-TFR-MAV"
ACCEPTANCE_CLASS = "all"


def _rule_hours(rule: str, fedramp_class: str, *, db_alias: str) -> int:
    row = (
        read_scope.node_relation(read_scope.DEFAULT_SCOPE, VdrTimeframe, db_alias=db_alias)
        .filter(rule=rule, fedramp_class=fedramp_class, pain="", exposure="")
        .first()
    )
    if row is None:
        raise LookupError(f"no {rule} timeframe row for class {fedramp_class}; the seed is incomplete")
    return int(row.hours)


def evaluation_hours(fedramp_class: str, *, db_alias: str = "default") -> int:
    """Hours from detection within which a vulnerability should be evaluated (`VER-TFR-EVU`) for the class."""
    if fedramp_class not in CLASSES:
        raise ValueError(f"{fedramp_class!r} is not a FedRAMP class; expected one of {', '.join(CLASSES)}")
    return _rule_hours(EVALUATION_RULE, fedramp_class, db_alias=db_alias)


def acceptance_hours(*, db_alias: str = "default") -> int:
    """Hours after which a vulnerability not mitigated or remediated is an accepted vulnerability (`VER-TFR-MAV`)."""
    return _rule_hours(ACCEPTANCE_RULE, ACCEPTANCE_CLASS, db_alias=db_alias)
