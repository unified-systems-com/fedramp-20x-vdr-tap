# fedramp-20x-vdr-tap

A TAP plugin (`fedramp_20x_vdr`) that evaluates each vulnerability finding under FedRAMP 20x Vulnerability Detection and Response, seeds FedRAMP's timeframe tables as data, and computes the deadlines they imply. It starts from the worst case for every factor and lowers a factor only when evidence is attached.

Read first: [`specs/spec-fedramp-20x-vdr-v0.md`](specs/spec-fedramp-20x-vdr-v0.md).

## What this plugin owns

- `vdr_evaluation`: one per finding, with `likely_exploitable`, `internet_reachable` and `pain`, all `null` until observed. Null reads as the worst case in every Search.
- `vdr_timeframe`: 53 seeded rows, one per cell of FedRAMP's timeframe tables (VDR-TFR-PVR, VER-TFR-EVU, VER-TFR-MAV), each quoting the page cell it was read from.
- `EVALUATES_COMPLIANCE_FINDING` and `CITES_FACTOR_EVIDENCE`, the two edges that tie an evaluation to a finding and to the evidence that lowers a factor.
- `data/evidence_basis.json`, the closed list of bases an evidence edge may give.

## What lives elsewhere

- Findings, vulnerabilities, evidence, scanners and scan runs: [`compliance-core-tap`](https://github.com/unified-systems-com/compliance-core-tap). This plugin depends on it.
- The detection time (`first_detected_at`): compliance_core, tracked in Issue# 43 - compliance-core-tap.
- Date arithmetic in queries: Gryphon, tracked in Issue# 1064 - tap.
- Pages and panels: none in v0.

## What is built, and what is not

Built: the two models, two edges, the timeframe seed and the evidence-basis list. Not built yet: the VDR-max collector, and the deadline and incident Searches. The spec marks each requirement's status.

## Stand it up

The plugin is developed against a TAP session with the checkout installed editable:

    spawn-session.sh <label> --from 'git+https://github.com/unified-systems-com/fedramp-20x-vdr-tap@<tag>#ci' --dev-plugins fedramp_20x_vdr

Run its tests inside that session's `web` container, never on the host:

    scripts/dc exec web uv run python -m tap_plugins.validate_plugin tap_plugin/fedramp_20x_vdr --strict
    scripts/dc exec web uv run pytest --pyargs tap_plugin.fedramp_20x_vdr

Licensed under Apache-2.0.
