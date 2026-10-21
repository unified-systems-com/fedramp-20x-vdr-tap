"""The PAIN levels, the exposure column and the fail-safe profile reduction (`req-fedramp-20x-vdr-pain`, `-reach-8`).

Pure and Django-free: it reads no node, imports nothing from the grid and gives the same output for the same input, so a
method plugin can import it anywhere. It holds what a method does not decide: the ordered levels FedRAMP publishes, the
column of the timeframe table a finding falls in, and the one reduction every method with a confidentiality, integrity
and availability requirement (CR, IR, AR) needs. It scores nothing and carries no weight or threshold.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence

#: FedRAMP's PAIN levels from the lowest to the highest. FedRAMP publishes no timeframe for N1 (`req-fedramp-20x-vdr-low-pain`).
LEVELS: tuple[str, ...] = ("N1", "N2", "N3", "N4", "N5")

#: The three columns of the remediation table, by what is known of the finding.
COLUMN_LEV_IRV = "lev_irv"  # likely exploitable and internet-reachable
COLUMN_LEV_NIRV = "lev_nirv"  # likely exploitable, not internet-reachable
COLUMN_NLEV = "nlev"  # not likely exploitable
COLUMNS: tuple[str, ...] = (COLUMN_LEV_IRV, COLUMN_LEV_NIRV, COLUMN_NLEV)

#: The order of a profile value, lowest first; the reduction takes the highest.
PROFILE_ORDER: tuple[str, ...] = ("low", "medium", "high")
Profile = Sequence[str | None]


def level_rank(level: str) -> int:
    """The position of a level (N1 is 0); a value outside N1 to N5 is refused."""
    try:
        return LEVELS.index(level)
    except ValueError:
        raise ValueError(f"{level!r} is not a PAIN level; expected one of {', '.join(LEVELS)}") from None


def exposure_column(likely_exploitable: bool, internet_reachable: bool) -> str:
    """The column a finding falls in. Not likely exploitable is `nlev` whatever its reachability."""
    if not likely_exploitable:
        return COLUMN_NLEV
    return COLUMN_LEV_IRV if internet_reachable else COLUMN_LEV_NIRV


def reduce_profiles(profiles: Iterable[Profile | None]) -> tuple[str, str, str]:
    """The per-objective maximum of a list of `(cr, ir, ar)` triples, in the order low, medium, high.

    A `None` value, a `None` profile and an empty list all count as high: a program with no profile raises the result,
    the fail-safe of the stair-step. A value outside low, medium and high is refused.
    """
    collected = list(profiles)
    if not collected:
        return ("high", "high", "high")
    result: list[int] = [0, 0, 0]
    for profile in collected:
        values: Sequence[str | None] = (None, None, None) if profile is None else profile
        if len(values) != 3:
            raise ValueError(f"a profile is a (cr, ir, ar) triple, not {tuple(values)!r}")
        for position, value in enumerate(values):
            rank = _profile_rank(value)
            result[position] = max(result[position], rank)
    return (PROFILE_ORDER[result[0]], PROFILE_ORDER[result[1]], PROFILE_ORDER[result[2]])


def _profile_rank(value: str | None) -> int:
    if value is None:
        return len(PROFILE_ORDER) - 1
    try:
        return PROFILE_ORDER.index(value)
    except ValueError:
        raise ValueError(f"{value!r} is not a profile value; expected one of {', '.join(PROFILE_ORDER)}") from None
