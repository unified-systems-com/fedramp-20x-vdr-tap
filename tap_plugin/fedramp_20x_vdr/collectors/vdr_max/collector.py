"""The VDR-max collector: an all-null evaluation for every open, vulnerability-linked finding.

A derived collector. Its input is the grid, not an outside system: it reads the compliance findings
that concern a vulnerability (``req-fedramp-20x-vdr-collector``), and the evaluations that already
exist, and submits one GRIFT batch holding an evaluation, with every factor unset, for each finding
that has none. An unset factor reads as the worst case in every Search
(``req-fedramp-20x-vdr-effective``), so one run makes every current finding an entry at VDR-max.

What it will not do is as much the contract as what it does. It never emits a node for a finding that
already has an evaluation, because a GRIFT node re-sent under an existing key overwrites the fields a
person set; it never deletes an evaluation, resolved finding or not; and it never evaluates a finding
with no vulnerability edge.

The collector reads the grid through Gryphon (``execute_gryphon_raw``), which is the one sanctioned
read path, and writes through ``submit_grift``, which is the one sanctioned write path. It calls no
outside service, so there is no network call to bound with a ceiling and no credential to resolve.

Spec: specs/spec-fedramp-20x-vdr-v0.md (req-fedramp-20x-vdr-collector).
"""

from __future__ import annotations

import uuid
from typing import Any

from tap_cares.collectors import CollectorBase
from tap_grid.gryphon.executor import execute_gryphon_raw

FINDING_TYPE = "compliance_core__compliance_finding"
EVALUATION_TYPE = "fedramp_20x_vdr__vdr_evaluation"
EVALUATES_EDGE = "EVALUATES_COMPLIANCE_FINDING__fedramp_20x_vdr"
BATCH_SOURCE = "plugins.fedramp_20x_vdr.collectors.vdr_max"

#: Open findings that concern a vulnerability. A finding with no vulnerability edge is not evaluated
#: in v0 (ruled 2026-10-16), and a resolved one is history. One row per finding and vulnerability
#: edge, so a finding linked to two vulnerabilities appears twice and is de-duplicated below.
OPEN_LINKED_FINDINGS = (
    "MATCH (f:compliance_core__compliance_finding)"
    "-[:CONCERNS_COMPLIANCE_VULNERABILITY__compliance_core]->"
    "(v:compliance_core__compliance_vulnerability) "
    'WHERE f.data.status = "open" '
    "RETURN f.data.source AS source, f.data.source_key AS source_key"
)

#: Every evaluation on the grid, whatever its factors say: a person's evaluation is never touched.
EXISTING_EVALUATIONS = (
    "MATCH (e:fedramp_20x_vdr__vdr_evaluation) "
    "RETURN e.data.finding_source AS source, e.data.finding_source_key AS source_key"
)

_SITE_RUN_STARTED = "700d"
_SITE_UNKEYED_FINDINGS = "8229"
_SITE_NOTHING_TO_DO = "15e7"
_SITE_BATCH_SUBMITTED = "d359"
_SITE_READ_SHAPE = "c39d"

Key = tuple[str, str]


class VdrMaxCollectorError(RuntimeError):
    """The grid answered in a shape this collector does not understand; the run stops."""


class VdrMaxCollector(CollectorBase):
    """Gives every open, vulnerability-linked finding an evaluation with every factor unset."""

    def run(self) -> None:
        self.record_info(_SITE_RUN_STARTED, "RUN_STARTED", "Reading open findings that concern a vulnerability.")
        # The run reads the grid, not a listing surface in a source system, so there is no
        # completeness to claim; say so on the record rather than leave it silent.
        self.declare_no_surfaces()

        findings, unkeyed = self._read_keys(OPEN_LINKED_FINDINGS)
        existing, _ = self._read_keys(EXISTING_EVALUATIONS)

        if unkeyed:
            self.record_warn(
                _SITE_UNKEYED_FINDINGS,
                "UNKEYED_FINDINGS",
                f"{unkeyed} linked finding(s) have no source or source_key, so no evaluation can name them; "
                "they were skipped, not defaulted.",
                message_data={"count": unkeyed},
            )

        missing = sorted(findings - existing)
        if not missing:
            self.summary = f"No new evaluations: {len(findings)} open linked finding(s), all already evaluated" + (
                f"; {unkeyed} skipped for want of a key." if unkeyed else "."
            )
            self.record_info(_SITE_NOTHING_TO_DO, "NOTHING_TO_DO", self.summary)
            return

        self.submit_grift(self._document(missing))
        self.summary = f"Submitted {len(missing)} new evaluation(s) for {len(findings)} open linked finding(s)" + (
            f"; {unkeyed} skipped for want of a key." if unkeyed else "."
        )
        self.record_info(
            _SITE_BATCH_SUBMITTED,
            "BATCH_SUBMITTED",
            self.summary,
            message_data={"new_evaluations": len(missing), "open_linked_findings": len(findings)},
        )

    def _read_keys(self, query: str) -> tuple[set[Key], int]:
        """Run a Gryphon query that returns (source, source_key) rows; split off the ones with no key."""
        envelope = execute_gryphon_raw(query, {})
        rows = envelope.get("rows")
        if rows is None and envelope.get("nodes") == [] and envelope.get("edges") == []:
            # Observed 2026-10-19: a query that matches nothing returns the bare empty envelope with
            # no "rows" key at all. That is an answer (zero rows), not a malformed reply.
            rows = []
        if not isinstance(rows, list):
            self.record_error(
                _SITE_READ_SHAPE,
                "READ_SHAPE",
                "The Gryphon read did not return a list of rows.",
                message_data={"keys": sorted(envelope)},
            )
            raise VdrMaxCollectorError("The Gryphon read did not return rows.")
        keys: set[Key] = set()
        unkeyed = 0
        for row in rows:
            source, source_key = row.get("source"), row.get("source_key")
            if not source or not source_key:
                unkeyed += 1
                continue
            keys.add((str(source), str(source_key)))
        return keys, unkeyed

    @staticmethod
    def _document(missing: list[Key]) -> dict[str, Any]:
        """One batch: an evaluation per missing finding, each with the edge that names its finding."""
        nodes: list[dict[str, Any]] = []
        edges: list[dict[str, Any]] = []
        for index, (source, source_key) in enumerate(missing):
            ref = f"evaluation-{index}"
            nodes.append(
                {
                    "entity": {
                        "ref": ref,
                        "entity_type": EVALUATION_TYPE,
                        "name": f"VDR {source_key}",
                        "dimensions": {"fedramp.rule": "vdr"},
                    },
                    # Only the identity. Every factor, the evaluator, the time and the rationale are
                    # left out so they stay null: unobserved, which every Search reads as the worst case.
                    "node": {"finding_source": source, "finding_source_key": source_key},
                }
            )
            edges.append(
                {
                    "entity": {
                        "ref": f"evaluates-{index}",
                        "entity_type": "edge",
                        "name": EVALUATES_EDGE,
                        "dimensions": {"fedramp.rule": "vdr"},
                    },
                    "edge": {
                        "from_ref": ref,
                        "to_key": {"entity_type": FINDING_TYPE, "key": {"source": source, "source_key": source_key}},
                        "edge_type": EVALUATES_EDGE,
                        "properties": {},
                    },
                }
            )
        return {
            "metadata": {"grift_version": "0"},
            "_reserved": {},
            "batches": [
                {
                    "batch_entity": {
                        "entity_id": str(uuid.uuid4()),
                        "entity_type": "batch",
                        "name": f"FedRAMP 20x VDR max evaluations ({len(missing)})",
                        "dimensions": {},
                    },
                    "batch_node": {
                        "source": BATCH_SOURCE,
                        "name": f"FedRAMP 20x VDR max evaluations ({len(missing)})",
                        "description": "An evaluation with every factor unset for each open finding that "
                        "concerns a vulnerability and has none.",
                        "description_json": {
                            "format": "tap.fedramp_20x_vdr.collection-v0",
                            "data": {"new_evaluations": len(missing)},
                        },
                    },
                    "nodes": nodes,
                    "edges": edges,
                }
            ],
        }
