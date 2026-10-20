"""The coverage snapshot collector: the classification-mapping summary, recorded on a schedule.

A derived collector (``req-fedramp-20x-vdr-coverage-snapshot``). The work is compliance_core's
``SearchSnapshotCollector``; this subclass names the one Search to record and the plugin that owns the
report, and nothing else. It reads the grid and calls no outside service, so it needs no credential and no
call ceiling.

The Search is the playground's classification-mapping summary (``dimension-mapping-summary``), named by
entity id because collectors cannot yet carry per-instance configuration (ruled 2026-10-20: hard-coded for
the demo). The id is the entity id the playground's seed gives that Search; the two must never differ, and a
grid without the Search fails the run with an error naming the id and writes nothing.

Spec: specs/spec-fedramp-20x-vdr-v0.md (req-fedramp-20x-vdr-coverage-snapshot).
"""

from __future__ import annotations

from tap_plugin.compliance_core.collectors.search_snapshot import SearchSnapshotCollector

#: The playground's classification-mapping summary Search (``dimension-mapping-summary``).
COVERAGE_SUMMARY_SEARCH_ID = "01a15b2f-df3b-7569-bf22-9ead3f816b84"


class CoverageSnapshotCollector(SearchSnapshotCollector):
    """Records the classification-mapping summary as a ``compliance_search_snapshot`` each run."""

    SOURCE = "fedramp_20x_vdr"
    SEARCH_ENTITY_IDS = (COVERAGE_SUMMARY_SEARCH_ID,)
