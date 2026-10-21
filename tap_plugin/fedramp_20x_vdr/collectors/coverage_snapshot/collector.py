"""The coverage snapshot collector: the two coverage summaries, recorded on a schedule.

A derived collector (``req-fedramp-20x-vdr-coverage-snapshot``). The work is compliance_core's
``SearchSnapshotCollector``; this subclass names the Searches to record and the plugin that owns the
report, and nothing else. It reads the grid and calls no outside service, so it needs no credential and no
call ceiling.

The Searches are the playground's classification-mapping summary and its responsibility-coverage summary (both
``dimension-mapping-summary``), named by entity id because collectors cannot yet carry per-instance
configuration (ruled 2026-10-20: hard-coded for the demo). Each id is the entity id the playground's seed gives
its Search; the two must never differ, and a grid missing a Search fails the run with an error naming the id and
writes nothing (the base validates every Search before it writes any snapshot).

Spec: specs/spec-fedramp-20x-vdr-v0.md (req-fedramp-20x-vdr-coverage-snapshot).
"""

from __future__ import annotations

from tap_plugin.compliance_core.collectors.search_snapshot import SearchSnapshotCollector

#: The playground's classification-mapping summary Search (``dimension-mapping-summary``).
COVERAGE_SUMMARY_SEARCH_ID = "01a15b2f-df3b-7569-bf22-9ead3f816b84"
#: The playground's responsibility-coverage summary Search (``dimension-mapping-summary``).
RESPONSIBILITY_COVERAGE_SEARCH_ID = "01a15fdf-61ef-710d-b5d3-e3a7ae238a40"


class CoverageSnapshotCollector(SearchSnapshotCollector):
    """Records each coverage summary as a ``compliance_search_snapshot`` per run."""

    SOURCE = "fedramp_20x_vdr"
    SEARCH_ENTITY_IDS = (COVERAGE_SUMMARY_SEARCH_ID, RESPONSIBILITY_COVERAGE_SEARCH_ID)
