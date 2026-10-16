# FedRAMP 20x VDR Plugin Specification

**`fedramp_20x_vdr` evaluates every vulnerability finding under FedRAMP's Vulnerability Detection and Response rules and computes its deadlines. It starts from the worst case for every factor (a likely exploitable, internet-reachable vulnerability at PAIN N5) and lowers a factor only when evidence is attached, so an unevaluated finding is visible as such and is never mistaken for a safe one.**

## Plugin Identity

| Row | Value |
| --- | --- |
| Slug | `fedramp_20x_vdr` |
| Display name | `TAP FedRAMP 20x VDR` |
| Description | Per-finding FedRAMP 20x Vulnerability Detection and Response evaluation (LEV, IRV, PAIN), the remediation timeframe tables as data, and the deadlines they imply. |
| Kind | Leaf plugin. It consumes `compliance_core` (findings, vulnerabilities, evidence) and is consumed by the pages and products that show vulnerability posture. |

Default dimensions, one key for every node and edge the plugin ships:

| Key | Value | Why |
| --- | --- | --- |
| `fedramp.rule` | `vdr` | Names the FedRAMP rule family the object belongs to, so a filter can scope to VDR without naming a type. A future rule family from the same regime (the key-security-indicator family) takes its own value. The value is not the entity type. |

## Philosophy

FedRAMP's rules ask a provider to evaluate each detected vulnerability and then to act on a clock that depends on the answer. Most operators loading a new system have only part of what a full evaluation needs, often just a count of vulnerabilities per host. The plugin therefore works as a stair-step, a proof by contradiction. Step 0, "VDR-max", presumes the worst case for every finding and makes the mechanics, tables and pages work on the grid that already exists. Later steps attach evidence that contradicts a presumption, and each contradiction lowers one factor for one finding. Adding evidence never changes the model; it only fills fields that were null.

**Null is the worst case.** An unset factor is treated as the worst case, and that is actionable: it appears as work to do. A factor leaves null only through an evidence edge. The worst-case value is computed where it is read and is never written into the factor, so a reader cannot mistake "no one has looked" for "someone concluded N5". This is the grid's three-state rule (`req-grid-node-observation`): null is unobserved, an empty value is observed-empty, and a concrete value is an observation.

**What the plugin deliberately does not do.** It does not judge anything about a vulnerability's published facts (CVSS, EPSS, KEV, SSVC live on `compliance_vulnerability` in compliance_core). It is not a scanner and mints no findings. It ships no pages or panels in v0.

**Provenance markers.**
- *Observed:* the FedRAMP pages `reference/vulnerability-detection-and-response`, `reference/vulnerability-evaluation-and-reporting` and `definitions` at `https://www.fedramp.gov/2026/`, read as raw HTML on 2026-10-16 (fetched with curl, tags stripped), including the four timeframe tables and the N0 to N5 definitions (changelog 2026-10-05). The `compliance_core` v0.7.1 spec and models, read on 2026-10-16.
- *Documented:* the CycloneDX 1.6 JSON schema for the vulnerability analysis states and justifications, read from the CycloneDX repository's master branch on 2026-10-16.
- *Designed:* everything else in this document. Nothing here has been built or run.

## Goals

| # | Name | Description |
| --- | --- | --- |
| 1 | Worst Case By Default | Every finding has an evaluation whose unset factors read as the worst case. |
| 2 | Evidence Lowers | A factor leaves null only with an evidence edge naming the factor and its basis. |
| 3 | Tables As Data | FedRAMP's timeframe tables are seeded rows that cite their rule, not constants in code. |
| 4 | Computed Deadlines | Deadlines and overdue flags are computed from first detection and the seeded rows, never stored. |
| 5 | Additive Stages | Attaching evidence in a later stage fills fields; it adds no migration and rewrites no node. |

## Requirements

| RID | Name | Status | Notes |
| --- | --- | :---: | --- |
| req-fedramp-20x-vdr-evaluation | [Evaluation](#evaluation) | Proposed | `vdr_evaluation`, one per finding, factors null by default; the `EVALUATES_COMPLIANCE_FINDING` edge. |
| req-fedramp-20x-vdr-evidence | [Evidence For A Factor](#evidence-for-a-factor) | Proposed | The evidence edge with its factor and basis, and the check that a factor is non-null only with one. |
| req-fedramp-20x-vdr-timeframe | [Timeframe Rows](#timeframe-rows) | Proposed | `vdr_timeframe` and the seeded rows of the PVR tables, the evaluation deadlines and the acceptance limit. |
| req-fedramp-20x-vdr-effective | [Worst-Case Semantics](#worst-case-semantics) | Proposed | What an unset factor and an unset class mean; computed, never stored. |
| req-fedramp-20x-vdr-collector | [VDR-Max Collector](#vdr-max-collector) | Proposed | One derived collector that gives every open, vulnerability-linked finding an all-null evaluation. |
| req-fedramp-20x-vdr-deadlines | [Deadlines](#deadlines) | Proposed | Evaluation deadline, remediation deadline, overdue and acceptance flags as Searches. Depends on Issue# 43 - compliance-core-tap and Issue# 1064 - tap. |
| req-fedramp-20x-vdr-incidents | [Reportable Incidents](#reportable-incidents) | Proposed | The internet-reachable and non-internet-reachable incident rules as Searches. |
| req-fedramp-20x-vdr-nongoals | [v0 Non-Goals](#v0-non-goals) | Proposed | What v0 does not build. |
| req-fedramp-20x-vdr-report | [VDR Report](#v0-non-goals) | Backlog | The per-period report node and the published JSON schemas (VER-RPT-VDT, VER-RPT-PER, VER-TFR-MRH). |
| req-fedramp-20x-vdr-grouping | [Grouping](#v0-non-goals) | Backlog | Logical groupings of affected resources (VER-EVA-GRV). |
| req-fedramp-20x-vdr-false-positive | [False Positive](#v0-non-goals) | Backlog | Disposition of findings evaluated as false positives (VER-EVA-EFP). |
| req-fedramp-20x-vdr-accepted | [Accepted Vulnerability Record](#v0-non-goals) | Backlog | The explanation and supplementary information for accepted vulnerabilities (VER-RPT-AVI). |
| req-fedramp-20x-vdr-failures | [Failures Are Vulnerabilities](#v0-non-goals) | Backlog | Detection-process failures treated as vulnerabilities (VDR-CSO-FAV). |
| req-fedramp-20x-vdr-cadence | [Detection Cadence](#v0-non-goals) | Backlog | The scan-frequency rules (VDR-TFR-PDD, -PCD, -PSD, -MVX). |
| req-fedramp-20x-vdr-low-pain | [N0 And N1 Timeframes](#v0-non-goals) | Backlog | No published timeframe exists for PAIN N0 or N1; waits on FedRAMP. |
| req-fedramp-20x-vdr-class | [Class Node](#v0-non-goals) | Backlog | Replaces the v0 default class with a node that records the class. |
| req-fedramp-20x-vdr-partial | [Partly Evaluated Lookups](#v0-non-goals) | Backlog | Exact deadlines for evaluations with some factors set (v0 shows the worst-case bound); needs a per-finding lookup with a null default in Gryphon. |

### Evaluation
----
RID: `req-fedramp-20x-vdr-evaluation`

Status: `Proposed`

A `vdr_evaluation` is the plugin's answer for one finding: how likely it is to be exploited, whether the internet can reach it, and how badly an agency could be hurt. FedRAMP's evaluation rules (VER-EVA-ELX, VER-EVA-EIR, VER-EVA-EPA) ask for exactly these three outputs. The evaluation is a node rather than fields on the finding because it is a judgement made by a party at a time, with a rationale and evidence, while `compliance_finding` records an observation by a scanner.

#### Implementation

Entity type `fedramp_20x_vdr__vdr_evaluation`. Default dimensions `{"fedramp.rule": "vdr"}`.

| field | meaning |
| --- | --- |
| `finding_source`, `finding_source_key` | The `source` and `source_key` of the finding evaluated, copied verbatim. Together they are the identity: `NATURAL_KEY = ("finding_source", "finding_source_key")`. Required. |
| `likely_exploitable` | Boolean or `null`. The answer to VER-EVA-ELX. `null` is unobserved. |
| `internet_reachable` | Boolean or `null`. The answer to VER-EVA-EIR. |
| `pain` | One of `N0` to `N5`, or `null`. The Potential Agency Impact N-rating of VER-EVA-EPA. |
| `evaluator` | Who made the evaluation, as a string, or `null`. |
| `evaluated_at` | `format: date-time`, or `null`. When the evaluation was made. |
| `rationale` | Free text, or `null`. |

The identity mirrors the finding's identity so that an evaluation is found again on any grid the finding is. A check (`req-fedramp-20x-vdr-evaluation-4`) reports any evaluation whose key and the key of the finding it evaluates disagree. Display name is the finding's `source_key` prefixed `VDR `.

`EVALUATES_COMPLIANCE_FINDING` runs from a `vdr_evaluation` to a `compliance_finding`, declares the plain identity `{"discriminators": []}` and carries the default dimension. The identity admits one evaluation per finding; a check reports any finding pointed at by more than one such edge.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-fedramp-20x-vdr-evaluation-1 | Keyed By The Finding | Proposed | `vdr_evaluation` declares `NATURAL_KEY = ("finding_source", "finding_source_key")`; two writes for one finding are one node. | |
| req-fedramp-20x-vdr-evaluation-2 | Null Is Unobserved | Proposed | A factor, `evaluator`, `evaluated_at` or `rationale` that no writer set is stored as `null`, never as `false`, `N5` or an empty string. | |
| req-fedramp-20x-vdr-evaluation-3 | Values Are Checked | Proposed | `pain` outside `N0` to `N5`, a non-boolean factor, or an `evaluated_at` that is not a date-time is refused. | |
| req-fedramp-20x-vdr-evaluation-4 | Key Matches The Finding | Proposed | A check reports any evaluation whose key differs from the key of the finding it evaluates. | Detection after the fact: an edge cannot be validated against a node's fields at write time. |
| req-fedramp-20x-vdr-evaluation-5 | One Per Finding | Proposed | A check reports any finding with more than one `EVALUATES_COMPLIANCE_FINDING` edge pointing at it. | |

### Evidence For A Factor
----
RID: `req-fedramp-20x-vdr-evidence`

Status: `Proposed`

A factor is lowered only by evidence. The evidence is a `compliance_evidence` node from compliance_core, which already means "something that supports a verdict", and an edge from the evaluation says which factor it supports and on what basis. FedRAMP's own rule points the same way: VER-EVA-AIA says to assume exploitation can be automated unless there is evidence proving otherwise.

#### Implementation

`CITES_FACTOR_EVIDENCE` runs from a `vdr_evaluation` to a `compliance_evidence`. The existing `CITES_COMPLIANCE_EVIDENCE` runs from a finding, so it cannot be reused. The name is checked by `validate_plugin` against `req-tap-plugin-edge-naming` when built.

| property | meaning |
| --- | --- |
| `factor` | Required. One of `likely_exploitable`, `internet_reachable`. `pain` is refused in v0, because no basis list for lowering PAIN exists yet; a PAIN set before then has no possible evidence edge and so reads as null (`req-fedramp-20x-vdr-effective-6`). The value joins this list when its bases are specified. |
| `basis` | Required. A value from the closed list in `data/evidence_basis.json`. |
| `note` | Optional free text. |

Identity declares `{"discriminators": ["factor"]}`: one evidence node may support two factors of one evaluation, and those are two edges.

`data/evidence_basis.json` ships with a JSON Schema and a `description` at the top and on every entry. Its first content is the nine justification values of the CycloneDX 1.6 vulnerability analysis (`code_not_present`, `code_not_reachable`, `requires_configuration`, `requires_dependency`, `requires_environment`, `protected_by_compiler`, `protected_at_runtime`, `protected_at_perimeter`, `protected_by_mitigating_control`). They were designed for "not affected" and fit the likely-exploitable and internet-reachable factors; bases for lowering `pain` are not yet specified and are an open item. Extending the list changes data, not the model.

**What the edge proves and what it does not.** The model enforces that evidence exists, names the factor, and carries a basis from a closed list; a check also requires that the evidence is cited by the evaluated finding itself through `CITES_COMPLIANCE_EVIDENCE`, so evidence about nothing in particular cannot be attached to an unrelated finding (`req-fedramp-20x-vdr-evidence-5`). That the evidence supports the chosen value is **human-attested**: the `evaluator` who set the factor vouches for it, and the edge records what they relied on. The plugin does not claim to verify the substance of evidence.

The check (`req-fedramp-20x-vdr-evidence-3`) is a Gryphon query run as a test and as a shipped Search: evaluations where a factor is non-null and no `CITES_FACTOR_EVIDENCE` edge for that factor exists, and evaluations where a factor is non-null but `evaluator` or `evaluated_at` is null.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-fedramp-20x-vdr-evidence-1 | Factor And Basis Required | Proposed | An evidence edge without `factor`, or with a `factor` or `basis` outside the lists, is refused. | |
| req-fedramp-20x-vdr-evidence-2 | One Edge Per Factor | Proposed | The same evidence node cited for two factors of one evaluation is two edges; cited twice for one factor is one. | |
| req-fedramp-20x-vdr-evidence-3 | Unsupported Factor Reported | Proposed | The check returns every evaluation with a non-null factor lacking an evidence edge for that factor, and every one with a non-null factor and a null `evaluator` or `evaluated_at`. | Detection after the fact; write-time enforcement is not possible because the node and its edges arrive in one batch. |
| req-fedramp-20x-vdr-evidence-5 | Evidence Belongs To The Finding | Proposed | A check returns every `CITES_FACTOR_EVIDENCE` target that the evaluated finding does not also cite through `CITES_COMPLIANCE_EVIDENCE`. | Relevance of the evidence to the value is attested by the evaluator, not verified. |
| req-fedramp-20x-vdr-evidence-6 | Pain Edges Refused In v0 | Proposed | A `CITES_FACTOR_EVIDENCE` edge with `factor` of `pain` is refused until a basis list for PAIN is specified. | |
| req-fedramp-20x-vdr-evidence-4 | Basis List Is Data | Proposed | `data/evidence_basis.json` validates against its schema at load, and a basis is added without a code change. | |

### Timeframe Rows
----
RID: `req-fedramp-20x-vdr-timeframe`

Status: `Proposed`

FedRAMP states its deadlines as tables. The plugin seeds each cell of those tables as a `vdr_timeframe` row that cites the rule and the date the page was read, so a changed table is a changed seed file and a reader can check any row against the source.

#### Implementation

Entity type `fedramp_20x_vdr__vdr_timeframe`. `NATURAL_KEY = ("rule", "fedramp_class", "pain", "exposure")`. Default dimensions `{"fedramp.rule": "vdr"}`.

| field | meaning |
| --- | --- |
| `rule` | The FedRAMP rule: `VDR-TFR-PVR`, `VER-TFR-EVU` or `VER-TFR-MAV`. |
| `fedramp_class` | `a`, `b`, `c` or `d`; `all` where a rule does not vary by class (`VER-TFR-MAV`). |
| `pain` | `N2` to `N5` for `VDR-TFR-PVR` rows; `""` for rules that have no PAIN dimension (observed-empty: the rule has none). |
| `exposure` | `lev_irv`, `lev_nirv` or `nlev` for `VDR-TFR-PVR` rows (the table columns "LEV + IRV", "LEV + NIRV", "NLEV"); `""` otherwise. |
| `hours` | Positive integer. The interval in whole hours, so that class D's 12 hours and the days of every other cell share one unit. |
| `canon_cell` | The cell exactly as the page states it (`4 days`, `12 hours`). |
| `canon_read_at` | Date the page was read. |
| `canon_url` | The page the cell comes from. |

Seed content, 53 rows: 48 `VDR-TFR-PVR` cells (four classes, four ratings N2 to N5, three exposures), four `VER-TFR-EVU` rows (14, 7, 5, 2 days), and one `VER-TFR-MAV` row (192 days). The class A and class B cells are identical on the page as read and are both seeded; they are not merged. There is no row for `N0` or `N1`: the page lists neither (observed 2026-10-16, after N0 was added on 2026-10-05), and the plugin does not fill the gap.

The seed is a GRIFT bundle in `grift/`, imported by `import_plugin_grift`, and a test checks `hours` against `canon_cell` so a conversion error cannot pass.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-fedramp-20x-vdr-timeframe-1 | Keyed By The Cell | Proposed | `vdr_timeframe` declares the key above; re-seeding is a no-op. | |
| req-fedramp-20x-vdr-timeframe-2 | Fifty-Three Rows | Proposed | The seed holds exactly 48 PVR rows, 4 EVU rows and 1 MAV row. | |
| req-fedramp-20x-vdr-timeframe-3 | Hours Match The Canon | Proposed | For every row, `hours` equals `canon_cell` converted exactly (days times 24, hours as stated). | |
| req-fedramp-20x-vdr-timeframe-4 | No Invented Rows | Proposed | No row exists for `pain` of `N0` or `N1`. | |
| req-fedramp-20x-vdr-timeframe-5 | Rows Cite Their Source | Proposed | Every row carries a non-empty `canon_cell`, `canon_read_at` and `canon_url`. | |

### Worst-Case Semantics
----
RID: `req-fedramp-20x-vdr-effective`

Status: `Proposed`

The effective value of a factor is what every deadline and incident rule uses. It is derived where it is read and is never written to the evaluation.

#### Implementation

| input | effective value when the input is `null` |
| --- | --- |
| `likely_exploitable` | `true` |
| `internet_reachable` | `true` |
| `pain` | `N5` |
| class of the system | `d`, the strictest, in v0 |

**A factor counts as set only when evidence backs it.** A non-null factor with no `CITES_FACTOR_EVIDENCE` edge for that factor, or on an evaluation whose `evaluator` or `evaluated_at` is null, is unsupported and reads as `null`, that is, as the worst case, in every incident Search. The invariant "a factor leaves null only with an evidence edge" is therefore enforced where the result is read and not merely audited afterwards. Whether Gryphon can express that test inside the incident query (a `NOT EXISTS` over the evidence edge, combined with the `IS NULL OR` predicates) is not verified; if it cannot, the incident Searches are shipped as the pair "supported" and "unsupported" and a page must show both, and this requirement stays `Proposed` until a way is shown.

In a Search the null case is written as `IS NULL OR = <value>`; no stored column holds an effective value. The class in v0 is one input to the shipped Searches, declared as `$fedramp_class` with the default `d` where a Search input can carry a default, and as a literal in the Search otherwise. It is deliberately the single place to change when a node that records the class exists (`req-fedramp-20x-vdr-class`, Backlog). A Search says on its face that the class was assumed.

**Fail closed for the partly evaluated case.** An exact deadline for an evaluation with some factors set needs the timeframe row for its own effective values, which needs a default for null inside a lookup that Gryphon does not have today (`req-fedramp-20x-vdr-partial`, Backlog). Setting a factor must never take a finding out of the deadline Searches, so v0 applies the worst-case row (class D, N5, `lev_irv`) to **every** open evaluation whatever its factors say. Observed in the four timeframe tables as read on 2026-10-16: every row and every column is non-decreasing as a factor is lowered (PAIN from N5 toward N2, exposure from `lev_irv` to `nlev`), so the worst-case row gives the earliest deadline any evaluation can have. It is a bound, never later than the true deadline. A Search lists every evaluation with at least one factor set and marks its deadline as the worst-case bound.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-fedramp-20x-vdr-effective-1 | Nothing Effective Is Stored | Proposed | No field of any node the plugin ships holds an effective or defaulted value. | |
| req-fedramp-20x-vdr-effective-2 | Null Reads As Worst Case | Proposed | In the shipped Searches an evaluation with all factors `null` is treated as likely exploitable, internet-reachable, N5. | |
| req-fedramp-20x-vdr-effective-3 | Class Is Assumed Visibly | Proposed | The class input defaults to `d` and the shipped Searches that use it say so in their description. | |
| req-fedramp-20x-vdr-effective-4 | Setting A Factor Never Removes A Deadline | Proposed | An evaluation with any factor set, with or without evidence, still appears in every deadline Search with the worst-case row applied, and is also listed in the "evaluated" Search with its deadline marked as the worst-case bound. | Closes the fail-open path found in review of the first draft. |
| req-fedramp-20x-vdr-effective-6 | Evidence Makes A Factor Count | Proposed | In every incident Search, a non-null factor with no evidence edge for that factor, or on an evaluation with a null `evaluator` or `evaluated_at`, reads as `null`. | See `req-fedramp-20x-vdr-incidents-5`. |
| req-fedramp-20x-vdr-effective-5 | Worst Case Is A Bound | Proposed | A test over the seeded rows shows that, for every class, lowering PAIN or moving the exposure from `lev_irv` toward `nlev` never shortens `hours`. | Observed property of the tables as read; the test fails if a future table breaks it. |

### VDR-Max Collector
----
RID: `req-fedramp-20x-vdr-collector`

Status: `Proposed`

The first stage starts from what the grid already holds. One derived collector reads the findings and writes an all-null evaluation for each, so that firing it once makes every current finding an entry at the worst case. Definition of done for v0: after one run, every open finding linked to a vulnerability has a `vdr_evaluation` with `likely_exploitable`, `internet_reachable` and `pain` all `null`. Whether there are several collectors, or one configurable collector, is a later decision.

#### Implementation

A `tap_cares` collector (built with the `build-collector` skill, asked for by the maintainer) that reads through Gryphon: findings with `status` `open` that have a `CONCERNS_COMPLIANCE_VULNERABILITY` edge. For each such finding that has no evaluation it emits one `vdr_evaluation` (key from the finding; every factor, `evaluator`, `evaluated_at` and `rationale` absent) and the `EVALUATES_COMPLIANCE_FINDING` edge, in one GRIFT batch. It never emits a node for a finding that already has an evaluation, because an upsert of a node would overwrite fields a person set. Resolved findings keep their evaluation untouched. A finding with no vulnerability edge is not evaluated in v0 (ruled 2026-10-16).

The collector needs no credentials and makes no external call.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-fedramp-20x-vdr-collector-1 | Every Linked Open Finding | Proposed | After one run, the count of evaluations equals the count of open findings linked to a vulnerability, each with all three factors `null`. | The v0 definition of done. |
| req-fedramp-20x-vdr-collector-2 | Idempotent | Proposed | A second run emits nothing and changes no node. | |
| req-fedramp-20x-vdr-collector-3 | Never Overwrites | Proposed | An evaluation with a factor, `evaluator` or `evaluated_at` set is not re-emitted by a later run. | |
| req-fedramp-20x-vdr-collector-4 | Unlinked Findings Skipped | Proposed | An open finding with no vulnerability edge receives no evaluation. | |
| req-fedramp-20x-vdr-collector-5 | Writes Through GRIFT | Proposed | The collector submits one GRIFT batch and aborts on rejection. | |

### Deadlines
----
RID: `req-fedramp-20x-vdr-deadlines`

Status: `Proposed`

Three clocks matter and each runs from a different instant. The evaluation deadline (VER-TFR-EVU) runs from detection: the provider should evaluate every vulnerability within 14, 7, 5 or 2 days for class A, B, C or D. The remediation deadline (VDR-TFR-PVR) is stated "from evaluation", and a vulnerability not fully mitigated or remediated within 192 days of evaluation is an accepted vulnerability (VER-TFR-MAV). The clock does not restart when PAIN is lowered (ruled 2026-10-16). The **exact** deadline of an evaluated finding therefore counts from `evaluated_at`, as the rules state, using the timeframe row for that finding's own effective factors; that computation is the partly evaluated Backlog item. The **v0 deadline** is a bound that is never later than the exact one: for every finding, evaluated or not, it counts from `first_detected_at` (the earliest possible anchor, because an evaluation cannot precede detection) and applies the worst-case row.

#### Implementation

Deadlines are shipped as Searches, computed on read, never stored. Detection time is `first_detected_at` on `compliance_finding` (Issue# 43 - compliance-core-tap). Adding an interval to a date and comparing with the current time is the Gryphon capability of Issue# 1064 - tap. Until both land, this requirement stays `Proposed` and the Searches are not shipped.

| Search | Meaning |
| --- | --- |
| evaluation overdue | Evaluations with `evaluated_at` null where `first_detected_at` plus the `VER-TFR-EVU` hours for the class is earlier than now. |
| remediation due | For every open evaluation: `first_detected_at` plus the `VDR-TFR-PVR` hours for the class at N5 and `lev_irv`, with the hours or days remaining. |
| remediation overdue | The same, restricted to those past the deadline. |
| acceptance reached | Open evaluations where `first_detected_at` plus the `VER-TFR-MAV` hours is earlier than now. |
| evaluated | Evaluations with at least one factor set, each marked as showing the worst-case bound (`req-fedramp-20x-vdr-effective`). |
| detection time unobserved | Evaluations whose finding has a `null` `first_detected_at`. No deadline is computed for them and none is defaulted; they are listed. |

Every Search above uses the v0 bound defined in the paragraph before this table, never the exact deadline, and says so in its description. The exact deadline for an evaluated finding belongs to the partly evaluated Backlog item until Gryphon can do the per-finding lookup. An implementation that counts an evaluated finding from `evaluated_at` while still applying the worst-case row is not conformant: that pairing can be later than the exact deadline.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-fedramp-20x-vdr-deadlines-1 | Computed On Read | Proposed | No deadline, overdue flag or remaining-time value is stored on any node. | |
| req-fedramp-20x-vdr-deadlines-2 | Class D Worst Case | Proposed | For a finding detected at time t, the remediation deadline in v0 is t plus 12 hours. | The class D, N5, LEV and IRV cell. |
| req-fedramp-20x-vdr-deadlines-3 | Unobserved Detection Is Listed | Proposed | A finding with null `first_detected_at` appears in the "detection time unobserved" Search and in no overdue Search. | |
| req-fedramp-20x-vdr-deadlines-4 | Bound Stated, Anchor Is Detection | Proposed | Each remediation and acceptance Search counts from `first_detected_at` for every finding, evaluated or not, applies the worst-case row, and its description says it is a bound. | Anchoring an evaluated finding on `evaluated_at` with the worst-case row is non-conformant. |
| req-fedramp-20x-vdr-deadlines-5 | Blocked Until The Dependencies Land | Proposed | The Searches are not shipped until `first_detected_at` and date arithmetic exist. | Issue# 43 - compliance-core-tap, Issue# 1064 - tap. |

### Reportable Incidents
----
RID: `req-fedramp-20x-vdr-incidents`

Status: `Proposed`

FedRAMP lets a provider treat certain vulnerabilities as reportable incidents until they are partly mitigated. Under VER-TFR-IRI an internet-reachable, likely exploitable vulnerability with PAIN above N3 is one; under VER-TFR-NRI a likely exploitable vulnerability that is not internet-reachable at N5 is one. The first is stated as "SHOULD" for classes C and D and "MAY" for A and B; the second is "SHOULD" for class D and "MAY" otherwise. Under the worst case every finding in the cohort is a reportable incident at class D, and the Search shows that.

#### Implementation

Two Searches over **every** open evaluation, taking the same class input as the deadlines. Neither needs a timeframe row, so the partly evaluated case is computed exactly, with the null cases written as `IS NULL OR`. The first returns evaluations whose effective factors are likely exploitable (`likely_exploitable` null or true), internet-reachable (`internet_reachable` null or true) and PAIN above N3 (`pain` null or in N4, N5). The second returns those likely exploitable, with `internet_reachable` false, and effective PAIN N5 (`pain` null or N5). Under the all-null worst case only the first returns rows; the second returns rows once an `internet_reachable` of false is recorded. Each Search states whether the class makes the rule a SHOULD or a MAY.

**Unsupported factors read as null.** The incident Searches count a factor as set only when evidence backs it (`req-fedramp-20x-vdr-effective`, "A factor counts as set only when evidence backs it"). An unsupported value therefore cannot take an evaluation out of an incident Search; it stays in as if the factor were null, and `req-fedramp-20x-vdr-evidence-3` additionally reports it. **Risk left open:** if Gryphon cannot express the evidence test inside the incident query, the fallback is the supported and unsupported pair described there, and the protection then depends on a page showing both.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-fedramp-20x-vdr-incidents-1 | Worst Case Is An Incident | Proposed | With the default class, every all-null evaluation appears in the internet-reachable incident Search. | |
| req-fedramp-20x-vdr-incidents-2 | Threshold Is Above N3 | Proposed | The internet-reachable Search requires effective PAIN greater than N3, and the other requires N5. | |
| req-fedramp-20x-vdr-incidents-3 | Modal Stated | Proposed | Each Search description says whether the rule is a SHOULD or a MAY for the class in use. | |
| req-fedramp-20x-vdr-incidents-4 | Partly Evaluated Is Computed | Proposed | An evaluation with an evidence-backed factor is placed by its effective values: `pain` of N3 leaves the first Search; `internet_reachable` of false moves a likely exploitable N5 into the second. | |
| req-fedramp-20x-vdr-incidents-5 | Unsupported Factor Reads As Null | Proposed | An evaluation with `pain` of N3, or `likely_exploitable` of false, and no evidence edge for that factor still appears in the first Search. | Verified by a test that writes the value without the edge. |

### v0 Non-Goals
----
RID: `req-fedramp-20x-vdr-nongoals`

Status: `Proposed`

The plugin does not, in v0:

- ship pages, panels or a layout; the Searches are the surface other pages read;
- mint findings, vulnerabilities, scanners or scan runs, or store a detection time (compliance_core owns them; Issue# 43 - compliance-core-tap);
- compute dates itself (Gryphon owns that; Issue# 1064 - tap);
- evaluate a finding that has no vulnerability edge, or a resolved one;
- compute the exact deadline for an evaluation with any factor set; v0 shows the worst-case bound (`req-fedramp-20x-vdr-partial`);
- invent a timeframe for PAIN N0 or N1 (`req-fedramp-20x-vdr-low-pain`);
- represent the system's class as anything but the default input (`req-fedramp-20x-vdr-class`);
- produce the per-period VDR report, grouping, false-positive or accepted-vulnerability records, detection cadence, or failures as vulnerabilities (the Backlog rows above).

## Model catalog

Design-time; superseded by the manifest once the owning requirement is `Implemented`.

| Model | Entity type | Category | Rationale |
| --- | --- | --- | --- |
| `vdr_evaluation` | `fedramp_20x_vdr__vdr_evaluation` | Judgement | A judgement by a party at a time, one per finding, kept apart from the scanner's observation. |
| `vdr_timeframe` | `fedramp_20x_vdr__vdr_timeframe` | Reference data | One cell of a FedRAMP table, so the table is data with a cited source. |

## Edge types

| Edge | From → To | Properties | Rationale |
| --- | --- | --- | --- |
| `EVALUATES_COMPLIANCE_FINDING` | `vdr_evaluation` → `compliance_finding` | none | Which finding an evaluation judges. |
| `CITES_FACTOR_EVIDENCE` | `vdr_evaluation` → `compliance_evidence` | `factor`, `basis`, `note` | The proof that lowers one factor; the existing finding-to-evidence edge cannot start at an evaluation. |

## Reference data

| Document | Contents | Seeded by |
| --- | --- | --- |
| `grift/timeframes.grift.json` | The 53 `vdr_timeframe` rows. | `import_plugin_grift` |
| `data/evidence_basis.json` | The closed list of evidence bases, with a schema. | Loaded by the plugin |
