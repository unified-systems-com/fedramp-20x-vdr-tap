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
| `vdr.scheme` | the evaluation's `scheme` | Stamped on every `vdr_evaluation` and its `EVALUATES_COMPLIANCE_FINDING` edge, from the node's `scheme` column, so a filter or page can scope to one algorithm (`max`, or another scheme's name) without reading the column. It is a copy for filtering, not the identity: the identity is the column (`req-fedramp-20x-vdr-evaluation-7`). Not stamped on timeframe rows. |

## Philosophy

FedRAMP's rules ask a provider to evaluate each detected vulnerability and then to act on a clock that depends on the answer. Most operators loading a new system have only part of what a full evaluation needs, often just a count of vulnerabilities per host. The plugin therefore works as a stair-step, a proof by contradiction. Step 0, "VDR-max", presumes the worst case for every finding and makes the mechanics, tables and pages work on the grid that already exists. Later steps attach evidence that contradicts a presumption, and each contradiction lowers one factor for one finding. Adding evidence never changes the model; it only fills fields that were null.

**Null is the worst case.** An unset factor is treated as the worst case, and that is actionable: it appears as work to do. A factor leaves null, in the **effective** sense that every Search uses, only through an evidence edge. The stored fields are raw inputs, not answers: a concrete value without evidence can be stored (an edge cannot be checked when its node is written), and it is read as null by every shipped Search, so a page or Search that reads `vdr_evaluation` factors directly instead of through the shipped Searches is non-conformant (`req-fedramp-20x-vdr-effective-7`). The worst-case value is computed where it is read and is never written into the factor, so a reader cannot mistake "no one has looked" for "someone concluded N5". This is the grid's three-state rule (`req-grid-node-observation`): null is unobserved, an empty value is observed-empty, and a concrete value is an observation.

**What the plugin deliberately does not do.** It does not judge anything about a vulnerability's published facts (CVSS, EPSS, KEV, SSVC live on `compliance_vulnerability` in compliance_core). It is not a scanner and mints no findings. It ships no pages or panels in v0.

**Provenance markers.**
- *Observed:* the FedRAMP pages `reference/vulnerability-detection-and-response`, `reference/vulnerability-evaluation-and-reporting` and `definitions` at `https://www.fedramp.gov/2026/`, read as raw HTML on 2026-10-16 (fetched with curl, tags stripped), including the four timeframe tables and the N0 to N5 definitions (changelog 2026-10-05). The `compliance_core` v0.7.1 spec and models, read on 2026-10-16.
- *Documented:* the CycloneDX 1.6 JSON schema for the vulnerability analysis states and justifications, read from the CycloneDX repository's master branch on 2026-10-16.
- *Designed:* everything else in this document. Nothing here has been built or run.

## Goals

| # | Name | Description |
| --- | --- | --- |
| 1 | Worst Case By Default | Every finding has an evaluation whose unset factors read as the worst case. |
| 2 | Evidence Lowers | A factor reads as anything but the worst case only with an evidence edge naming the factor and its basis. |
| 3 | Tables As Data | FedRAMP's timeframe tables are seeded rows that cite their rule, not constants in code. |
| 4 | Computed Deadlines | Deadlines and overdue flags are computed from first detection and the seeded rows, never stored. |
| 5 | Additive Stages | Attaching evidence in a later stage fills fields; it adds no migration and rewrites no node. |

## Requirements

| RID | Name | Status | Notes |
| --- | --- | :---: | --- |
| req-fedramp-20x-vdr-evaluation | [Evaluation](#evaluation) | In Development | `vdr_evaluation`, one per finding per scheme, factors null by default; the `EVALUATES_COMPLIANCE_FINDING` edge. |
| req-fedramp-20x-vdr-evidence | [Evidence For A Factor](#evidence-for-a-factor) | In Development | The evidence edge with its factor and basis, and the check that a factor is non-null only with one. |
| req-fedramp-20x-vdr-timeframe | [Timeframe Rows](#timeframe-rows) | Implemented | `vdr_timeframe` and the seeded rows of the PVR tables, the evaluation deadlines and the acceptance limit. |
| req-fedramp-20x-vdr-effective | [Worst-Case Semantics](#worst-case-semantics) | Proposed | What an unset factor and an unset class mean; computed, never stored. |
| req-fedramp-20x-vdr-collector | [VDR-Max Collector](#vdr-max-collector) | Implemented | One derived collector that gives every open, vulnerability-linked finding an all-null evaluation. |
| req-fedramp-20x-vdr-coverage-snapshot | [Coverage Snapshot Collector](#coverage-snapshot-collector) | Implemented | One derived collector, a subclass of compliance_core's `SearchSnapshotCollector`, that records the classification-mapping summary hourly as a `compliance_search_snapshot`. |
| req-fedramp-20x-vdr-reach | [Finding Reach](#finding-reach) | Implemented | The owner of each open finding (its program by the `RUNS_PACKAGE` closure, else its container) and the programs involved, with the fail-safe reduction of profiles. Importable and a `module` Search runner; computed on read; reads no profile. |
| req-fedramp-20x-vdr-pain | [PAIN Levels And Deadlines](#pain-levels-and-deadlines) | Implemented | The ordered levels N1 to N5, the exposure column and `deadline_hours` from the timeframe rows, for any method plugin that supplies a level. |
| req-fedramp-20x-vdr-deadlines | [Deadlines](#deadlines) | Implemented | Evaluation deadline, remediation deadline, overdue and acceptance flags as Searches. Depends on Issue# 43 - compliance-core-tap and Issue# 1064 - tap. |
| req-fedramp-20x-vdr-incidents | [Reportable Incidents](#reportable-incidents) | Implemented | The internet-reachable and non-internet-reachable incident rules as Searches. Ship condition: Gryphon must express the evidence test in one query (`-incidents-6`). |
| req-fedramp-20x-vdr-nongoals | [v0 Non-Goals](#v0-non-goals) | Proposed | What v0 does not build. |
| req-fedramp-20x-vdr-report | [VDR Report](#v0-non-goals) | Backlog | The per-period report node and the published JSON schemas (VER-RPT-VDT, VER-RPT-PER, VER-TFR-MRH). |
| req-fedramp-20x-vdr-grouping | [Grouping](#v0-non-goals) | Backlog | Logical groupings of affected resources (VER-EVA-GRV). |
| req-fedramp-20x-vdr-false-positive | [False Positive](#v0-non-goals) | Backlog | Disposition of findings evaluated as false positives (VER-EVA-EFP). |
| req-fedramp-20x-vdr-accepted | [Accepted Vulnerability Record](#v0-non-goals) | Backlog | The explanation and supplementary information for accepted vulnerabilities (VER-RPT-AVI). |
| req-fedramp-20x-vdr-failures | [Failures Are Vulnerabilities](#v0-non-goals) | Backlog | Detection-process failures treated as vulnerabilities (VDR-CSO-FAV). |
| req-fedramp-20x-vdr-cadence | [Detection Cadence](#v0-non-goals) | Backlog | The scan-frequency rules (VDR-TFR-PDD, -PCD, -PSD, -MVX). |
| req-fedramp-20x-vdr-low-pain | [N0 And N1 Timeframes](#v0-non-goals) | Backlog | No published timeframe exists for PAIN N0 or N1; waits on FedRAMP. |
| req-fedramp-20x-vdr-reach-direct | [Direct Reachability](#finding-reach) | Backlog | Computing IRV from the network surface (public routes, listeners, protocol), the direct branch of the reachability model, instead of reading it from the evaluation. |
| req-fedramp-20x-vdr-reach-shipped | [Shipped Libraries](#finding-reach) | Backlog | Following `SHIPS_LIBRARY` from a package to the programs that load a library it ships. |
| req-fedramp-20x-vdr-class | [Class Node](#v0-non-goals) | Backlog | Replaces the v0 default class with a node that records the class. |
| req-fedramp-20x-vdr-partial | [Partly Evaluated Lookups](#v0-non-goals) | Backlog | Exact deadlines for evaluations with some factors set (v0 shows the worst-case bound); needs a per-finding lookup with a null default in Gryphon. |

### Evaluation
----
RID: `req-fedramp-20x-vdr-evaluation`

Status: `In Development`

A `vdr_evaluation` is the plugin's answer for one finding: how likely it is to be exploited, whether the internet can reach it, and how badly an agency could be hurt. FedRAMP's evaluation rules (VER-EVA-ELX, VER-EVA-EIR, VER-EVA-EPA) ask for exactly these three outputs. The evaluation is a node rather than fields on the finding because it is a judgement made by a party at a time, with a rationale and evidence, while `compliance_finding` records an observation by a scanner.

#### Implementation

Entity type `fedramp_20x_vdr__vdr_evaluation`. Default dimensions `{"fedramp.rule": "vdr"}`.

| field | meaning |
| --- | --- |
| `finding_source`, `finding_source_key` | The `source` and `source_key` of the finding evaluated, copied verbatim. Required. With `scheme` they are the identity: `NATURAL_KEY = ("finding_source", "finding_source_key", "scheme")`. |
| `scheme` | Free text, 1 to 64 characters, required. Names the algorithm or method that made this evaluation: `max` for the VDR-max collector, another name for another method. Part of the identity, so one finding can carry several evaluations, one per scheme, for comparison. The dimension `vdr.scheme` is stamped from it. |
| `likely_exploitable` | Boolean or `null`. The answer to VER-EVA-ELX. `null` is unobserved. |
| `internet_reachable` | Boolean or `null`. The answer to VER-EVA-EIR. |
| `pain` | One of `N0` to `N5`, or `null`. The Potential Agency Impact N-rating of VER-EVA-EPA. |
| `evaluator` | Who made the evaluation, as a string, or `null`. |
| `evaluated_at` | `format: date-time`, or `null`. When the evaluation was made. |
| `rationale` | Free text, or `null`. |

The identity mirrors the finding's identity, plus the scheme, so that an evaluation is found again on any grid the finding is. A dimension cannot be part of an identity (the generated search ignores dimensions, `req-grid-entity-natural-key-10`), which is why the scheme is a column and the dimension a copy. A check (`req-fedramp-20x-vdr-evaluation-4`) reports any evaluation whose key and the key of the finding it evaluates disagree. Display name is the finding's `source_key` prefixed `VDR `.

`EVALUATES_COMPLIANCE_FINDING` runs from a `vdr_evaluation` to a `compliance_finding`, declares the plain identity `{"discriminators": []}` and carries the default dimension. The identity admits one evaluation per finding per scheme; a check reports any finding pointed at by more than one such edge with the same `vdr.scheme`.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-fedramp-20x-vdr-evaluation-1 | Keyed By The Finding And Scheme | Implemented | `vdr_evaluation` declares `NATURAL_KEY = ("finding_source", "finding_source_key", "scheme")`; two writes for one finding and one scheme are one node, and one finding with two schemes has two nodes. | Was keyed by the finding alone (v0.1.0); changed 2026-10-21 so several algorithms can evaluate one finding. |
| req-fedramp-20x-vdr-evaluation-2 | Null Is Unobserved | Implemented | A factor, `evaluator`, `evaluated_at` or `rationale` that no writer set is stored as `null`, never as `false`, `N5` or an empty string. | |
| req-fedramp-20x-vdr-evaluation-3 | Values Are Checked | Implemented | `pain` outside `N0` to `N5`, a non-boolean factor, or an `evaluated_at` that is not a date-time is refused. | |
| req-fedramp-20x-vdr-evaluation-6 | Pain Stays Null In v0 | Implemented | A write that sets `pain` to a non-null value is refused in v0, because no PAIN evidence edge can exist (`req-fedramp-20x-vdr-evidence-6`); the refusal is lifted when the PAIN basis list is specified. | Write-time enforcement is possible here because it needs no edge. |
| req-fedramp-20x-vdr-evaluation-4 | Key Matches The Finding | Proposed | A check reports any evaluation whose `finding_source` and `finding_source_key` differ from the `source` and `source_key` of the finding it evaluates; `scheme` is not compared. | Detection after the fact: an edge cannot be validated against a node's fields at write time. |
| req-fedramp-20x-vdr-evaluation-5 | One Per Finding Per Scheme | Proposed | A check reports any finding with more than one `EVALUATES_COMPLIANCE_FINDING` edge pointing at it from evaluations of the same scheme. | |
| req-fedramp-20x-vdr-evaluation-7 | Scheme Is In The Key | Implemented | `scheme` is a required column of 1 to 64 characters, free text; a write without it, with an empty one or with a longer one is refused. | George ruled 2026-10-21: free text, not a closed list. |
| req-fedramp-20x-vdr-evaluation-8 | Dimension Follows The Column | Proposed | Every evaluation and its edge carry `vdr.scheme` equal to the node's `scheme`; a check reports any that differ. | The dimension is a copy for display and filtering by a person; the column is the identity and the only thing a shipped Search reads (`effective-8`). The write is not rejected on a mismatch, because a dimension is stamped by the writer and cannot be validated against a column at write time; detection is the check. |
| req-fedramp-20x-vdr-evaluation-9 | Existing Evaluations Become max | Implemented | The schema migration adds `scheme` and sets it to `max` on every evaluation that exists, and the collector's next run finds those rows by the new key and writes none beside them. | Without it the new key finds no match and the collector would add a second `max` evaluation for every finding. The migration also stamps `vdr.scheme: max` on those nodes and their edges. |

### Evidence For A Factor
----
RID: `req-fedramp-20x-vdr-evidence`

Status: `In Development`

A factor is lowered only by evidence. The evidence is a `compliance_evidence` node from compliance_core, which already means "something that supports a verdict", and an edge from the evaluation says which factor it supports and on what basis. FedRAMP's own rule points the same way: VER-EVA-AIA says to assume exploitation can be automated unless there is evidence proving otherwise.

#### Implementation

`CITES_FACTOR_EVIDENCE` runs from a `vdr_evaluation` to a `compliance_evidence`. The existing `CITES_COMPLIANCE_EVIDENCE` runs from a finding, so it cannot be reused. The name is checked by `validate_plugin` against `req-tap-plugin-edge-naming` when built.

| property | meaning |
| --- | --- |
| `factor` | Required. One of `likely_exploitable`, `internet_reachable`. `pain` is refused in v0, because no basis list for lowering PAIN exists yet; a PAIN set before then has no possible evidence edge and so reads as null (`req-fedramp-20x-vdr-effective-6`). The value joins this list when its bases are specified. |
| `basis` | Required. A value from the closed list in `data/evidence_basis.json`. |
| `note` | Optional free text. |

Identity declares `{"discriminators": ["factor"]}`: one evidence node may support two factors of one evaluation, and those are two edges.

`data/evidence_basis.json` ships with a JSON Schema and a `description` at the top and on every entry. Its first content is the nine justification values of the CycloneDX 1.6 vulnerability analysis (`code_not_present`, `code_not_reachable`, `requires_configuration`, `requires_dependency`, `requires_environment`, `protected_by_compiler`, `protected_at_runtime`, `protected_at_perimeter`, `protected_by_mitigating_control`). They were designed for "not affected" and fit the likely-exploitable and internet-reachable factors; bases for lowering `pain` are not yet specified and are an open item. The `basis` property of the edge definition carries the same keys as an enum, because an edge property schema cannot read a data file, and a test pins the two equal. Extending the list is an edit to those two data files, never to code.

**What the edge proves and what it does not.** The model enforces that evidence exists, names the factor, and carries a basis from a closed list; a check also requires that the evidence is cited by the evaluated finding itself through `CITES_COMPLIANCE_EVIDENCE`, so evidence about nothing in particular cannot be attached to an unrelated finding (`req-fedramp-20x-vdr-evidence-5`). That the evidence supports the chosen value is **human-attested**: the `evaluator` who set the factor vouches for it, and the edge records what they relied on. The plugin does not claim to verify the substance of evidence.

The check (`req-fedramp-20x-vdr-evidence-3`) is a Gryphon query run as a test and as a shipped Search: evaluations where a factor is non-null and no `CITES_FACTOR_EVIDENCE` edge for that factor exists, and evaluations where a factor is non-null but `evaluator` or `evaluated_at` is null.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-fedramp-20x-vdr-evidence-1 | Factor And Basis Required | Implemented | An evidence edge without `factor`, or with a `factor` or `basis` outside the lists, is refused. | |
| req-fedramp-20x-vdr-evidence-2 | One Edge Per Factor | Implemented | The same evidence node cited for two factors of one evaluation is two edges; cited twice for one factor is one. | |
| req-fedramp-20x-vdr-evidence-3 | Unsupported Factor Reported | Proposed | The check returns every evaluation with a non-null factor lacking an evidence edge for that factor, and every one with a non-null factor and a null `evaluator` or `evaluated_at`. | Detection after the fact; write-time enforcement is not possible because the node and its edges arrive in one batch. |
| req-fedramp-20x-vdr-evidence-5 | Evidence Belongs To The Finding | Proposed | A check returns every `CITES_FACTOR_EVIDENCE` target that the evaluated finding does not also cite through `CITES_COMPLIANCE_EVIDENCE`. | Relevance of the evidence to the value is attested by the evaluator, not verified. |
| req-fedramp-20x-vdr-evidence-6 | Pain Edges Refused In v0 | Implemented | A `CITES_FACTOR_EVIDENCE` edge with `factor` of `pain` is refused until a basis list for PAIN is specified. | |
| req-fedramp-20x-vdr-evidence-4 | Basis List Is Data | Implemented | `data/evidence_basis.json` validates against its schema, and a basis is added by editing data: the list and the `basis` enum of the edge definition `CITES_FACTOR_EVIDENCE__fedramp_20x_vdr.edge.json`, which a test pins equal. | The edge definition's enum is the enforced copy because an edge property schema cannot read a data file; no Python changes. Tests: `test_vdr_timeframe.py::TestEvidenceBasisList`. |

### Timeframe Rows
----
RID: `req-fedramp-20x-vdr-timeframe`

Status: `Implemented`

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
| req-fedramp-20x-vdr-timeframe-1 | Keyed By The Cell | Implemented | `vdr_timeframe` declares the key above; re-seeding is a no-op. | |
| req-fedramp-20x-vdr-timeframe-2 | Fifty-Three Rows | Implemented | The seed holds exactly 48 PVR rows, 4 EVU rows and 1 MAV row. | |
| req-fedramp-20x-vdr-timeframe-3 | Hours Match The Canon | Implemented | For every row, `hours` equals `canon_cell` converted exactly (days times 24, hours as stated). | |
| req-fedramp-20x-vdr-timeframe-4 | No Invented Rows | Implemented | No row exists for `pain` of `N0` or `N1`. | |
| req-fedramp-20x-vdr-timeframe-5 | Rows Cite Their Source | Implemented | Every row carries a non-empty `canon_cell`, `canon_read_at` and `canon_url`. | |

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

**A factor counts as set only when evidence backs it.** A non-null factor with no `CITES_FACTOR_EVIDENCE` edge for that factor, whose evidence the evaluated finding does not also cite through `CITES_COMPLIANCE_EVIDENCE`, or on an evaluation whose `evaluator` or `evaluated_at` is null, is unsupported and reads as `null`, that is, as the worst case, in every incident Search. The invariant "a factor leaves null only with an evidence edge" is therefore enforced where the result is read and not merely audited afterwards. Whether Gryphon can express that test inside one incident query (a `NOT EXISTS` over the evidence edge, combined with the `IS NULL OR` predicates) is not verified. If it cannot, the incident Searches are not shipped and are not marked `Implemented`: the gap goes to Gryphon as a missing capability (`gryphon-defect-response`), and no split into two Searches that depends on a page showing both is accepted as a substitute (`req-fedramp-20x-vdr-incidents-6`). In v0 only `likely_exploitable` and `internet_reachable` can be evidence-backed, so PAIN-based transitions are deferred until PAIN has a basis list.

In a Search the null case is written as `IS NULL OR = <value>`; no stored column holds an effective value. The class in v0 is one input to the shipped Searches, declared as `$fedramp_class` with the default `d` where a Search input can carry a default, and as a literal in the Search otherwise. It is deliberately the single place to change when a node that records the class exists (`req-fedramp-20x-vdr-class`, Backlog). A Search says on its face that the class was assumed.

**Fail closed for the partly evaluated case.** An exact deadline for an evaluation with some factors set needs the timeframe row for its own effective values, which needs a default for null inside a lookup that Gryphon does not have today (`req-fedramp-20x-vdr-partial`, Backlog). Setting a factor must never take a finding out of the deadline Searches, so v0 applies the worst-case row (class D, N5, `lev_irv`) to **every** open evaluation whatever its factors say. Observed in the four timeframe tables as read on 2026-10-16: every row and every column is non-decreasing as a factor is lowered (PAIN from N5 toward N2, exposure from `lev_irv` to `nlev`), so the worst-case row gives the earliest deadline any evaluation can have. It is a bound, never later than the true deadline. A Search lists every evaluation with at least one factor set and marks its deadline as the worst-case bound.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-fedramp-20x-vdr-effective-1 | Nothing Effective Is Stored | Proposed | No field of any node the plugin ships holds an effective or defaulted value. | |
| req-fedramp-20x-vdr-effective-2 | Null Reads As Worst Case | Proposed | In the shipped Searches an evaluation with all factors `null` is treated as likely exploitable, internet-reachable, N5. | |
| req-fedramp-20x-vdr-effective-3 | Class Is Assumed Visibly | Proposed | The class input defaults to `d` and the shipped Searches that use it say so in their description. | |
| req-fedramp-20x-vdr-effective-4 | Setting A Factor Never Removes A Deadline | Implemented | An evaluation with any factor set, with or without evidence, still appears in every deadline Search with the worst-case row applied, and is also listed in the "evaluated" Search with its deadline marked as the worst-case bound. | Closes the fail-open path found in review of the first draft. |
| req-fedramp-20x-vdr-effective-6 | Evidence Makes A Factor Count | Implemented | In every incident Search, a non-null factor reads as `null` unless all three hold: an evidence edge for that factor exists, the evaluated finding also cites that evidence through `CITES_COMPLIANCE_EVIDENCE`, and `evaluator` and `evaluated_at` are set. | See `req-fedramp-20x-vdr-incidents-5` and `req-fedramp-20x-vdr-evidence-5`, which is part of this test and not only an audit. Test: only the factor edge exists, and the factor still reads as `null`. |
| req-fedramp-20x-vdr-effective-8 | Searches Read One Scheme | Implemented | Every shipped deadline and incident Search takes a `$scheme` input, default `max`, and filters on the evaluation's `scheme` column, never on the `vdr.scheme` dimension; none mixes schemes. A node whose dimension disagrees with its column is still placed by its column, so a mismatch cannot hide an evaluation or put another scheme's into the default Search. | Comparing schemes is a Search over two schemes, not a side effect of one. |
| req-fedramp-20x-vdr-effective-7 | Raw Factors Are Not Answers | Proposed | Shipped pages, panels and Searches read the effective values only through the shipped Searches; none reads a `vdr_evaluation` factor field directly. | A review item for every consumer. |
| req-fedramp-20x-vdr-effective-5 | Worst Case Is A Bound | Implemented | A test over the seeded rows shows that, for every class, lowering PAIN or moving the exposure from `lev_irv` toward `nlev` never shortens `hours`. | Observed property of the tables as read; the test fails if a future table breaks it. |

### VDR-Max Collector
----
RID: `req-fedramp-20x-vdr-collector`

Status: `Implemented`

The first stage starts from what the grid already holds. One derived collector reads the findings and writes an all-null evaluation for each, so that firing it once makes every current finding an entry at the worst case. Definition of done for v0: after one run, every open finding linked to a vulnerability has a `vdr_evaluation` of scheme `max` with `likely_exploitable`, `internet_reachable` and `pain` all `null`. Whether there are several collectors, or one configurable collector, is a later decision.

#### Implementation

A `tap_cares` collector (`tap_plugin/fedramp_20x_vdr/collectors/vdr_max/collector.py`, registered as `vdr_max` under scope `fedramp_20x_vdr`) that reads through Gryphon: findings with `status` `open` that have a `CONCERNS_COMPLIANCE_VULNERABILITY` edge. For each such finding that has no evaluation of scheme `max` it emits one `vdr_evaluation` (key from the finding, with `scheme` `max` and the dimension `vdr.scheme: max`; every factor, `evaluator`, `evaluated_at` and `rationale` absent) and the `EVALUATES_COMPLIANCE_FINDING` edge, in one GRIFT batch; the edge names its finding by natural key, so the collector handles no ids. A finding that has no `source` or `source_key` cannot be named, so it is skipped and counted in a warning, never defaulted. A Gryphon query that matches nothing returns the bare empty envelope with no `rows` key (observed 2026-10-19), which the collector reads as zero rows. It never emits a node for a finding that already has an evaluation of scheme `max`, because an upsert of a node would overwrite fields a person set; an evaluation of another scheme does not count, so a finding evaluated only by another scheme still gets its `max` evaluation. Resolved findings keep their evaluation untouched. A finding with no vulnerability edge is not evaluated in v0 (ruled 2026-10-16).

**Residual risk, observed 2026-10-19.** A GRIFT node sent under an existing natural key replaces the row: every field the node omits goes back to null (a test pins this). The collector therefore never sends a node for a key that already has an evaluation of scheme `max`, and never touches an evaluation of any other scheme. Its read of the existing evaluations and its submit are not atomic, so an evaluation a person wrote in the milliseconds between them would be blanked. The collector reads the existing set last to keep that window short, it is the step-0 bootstrap that runs before anyone evaluates, and the overwritten values remain in the node's history; GRIFT offers no insert-only form that would close the window.

The collector needs no credentials and makes no external call.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-fedramp-20x-vdr-collector-1 | Every Linked Open Finding | Implemented | On a grid with no evaluations, after one run every open finding linked to a vulnerability has exactly one evaluation of scheme `max`, each with all three factors `null`. | The v0 definition of done. On a grid that already has evaluations, a run adds one only for each open linked finding without a `max` evaluation and changes none (`-2`, `-3`). Reworded for the scheme 2026-10-21, so it is `Proposed` until the build. |
| req-fedramp-20x-vdr-collector-2 | Idempotent | Implemented | A second run emits nothing and changes no node. | |
| req-fedramp-20x-vdr-collector-3 | Never Overwrites | Implemented | An evaluation with a factor, `evaluator` or `evaluated_at` set is not re-emitted by a later run. | |
| req-fedramp-20x-vdr-collector-4 | Unlinked Findings Skipped | Implemented | An open finding with no vulnerability edge receives no evaluation. | |
| req-fedramp-20x-vdr-collector-5 | Writes Through GRIFT | Implemented | The collector submits one GRIFT batch and aborts on rejection. | |
| req-fedramp-20x-vdr-collector-7 | Disagreeing Reads Stop The Run | Implemented | If the set of connected evaluations holds a key the set of existing evaluations lacks, which cannot be true, the run records `INCONSISTENT_READ`, fails and submits nothing; a Gryphon read that raises fails the run likewise. | An empty-looking "existing" read is the one way the no-overwrite guard could fail open. Found in review of PR# 5. |
| req-fedramp-20x-vdr-collector-8 | Writes The max Scheme | Implemented | Every evaluation the collector writes has `scheme` `max` and the dimension `vdr.scheme: max`, on the node and on its edge. | George ruled 2026-10-21. |
| req-fedramp-20x-vdr-collector-9 | Other Schemes Are Not Its Business | Implemented | An evaluation of another scheme for the same finding is not counted as an existing `max` evaluation, is not reconnected, and is never touched; a finding evaluated only by another scheme still gets its `max` evaluation. | Several schemes must coexist so they can be compared. |
| req-fedramp-20x-vdr-collector-6 | Reconnects An Edge-Less Evaluation | Implemented | An evaluation of scheme `max` that exists but has no `EVALUATES_COMPLIANCE_FINDING` edge, for an open linked finding, gets that edge and nothing else; its node is not re-sent. | Every Search traverses the edge. Found in review of PR# 5. |

### Coverage Snapshot Collector
----
RID: `req-fedramp-20x-vdr-coverage-snapshot`

Status: `Implemented`

The classification mapping (`req-compliance-core-dimension-mapping`) says how much of the inventory carries the data classification it should, and an auditor wants that figure over time, not once. This plugin records it. A second derived collector, `coverage_snapshot`, runs the mapping-summary Search on a schedule and stores the rows as a `compliance_search_snapshot` (`req-compliance-core-search-snapshot`). The plugin owns this because the coverage figure is what its VDR work reports against; the Search it records belongs to the demo project and is seeded there.

#### Implementation

`tap_plugin/fedramp_20x_vdr/collectors/coverage_snapshot/collector.py` holds `CoverageSnapshotCollector`, a subclass of `tap_plugin.compliance_core.collectors.search_snapshot.SearchSnapshotCollector` (`req-compliance-core-search-snapshot-collector`) that sets two attributes and nothing else:

| attribute | value |
| --- | --- |
| `SOURCE` | `fedramp_20x_vdr` |
| `SEARCH_ENTITY_IDS` | `("01a15b2f-df3b-7569-bf22-9ead3f816b84",)`: the playground's classification-mapping summary Search (`dimension-mapping-summary`) |

It is registered in `apps.py` under scope `fedramp_20x_vdr` and key `coverage_snapshot`, beside `vdr_max`, with a name and description. It reads the grid and calls no outside service, so it needs no credential and no call ceiling.

The Search id is hard-coded in the subclass for the demo (ruled by George 2026-10-20). The id is minted once and is the entity id the playground's seed gives that Search (`req-rampart-20x-playground-snapshot-search`); the two must never differ. If the Search is not on the grid the base class fails the run with an error naming the id and writes nothing, so a deployment without the playground shows a failed run, not a bad snapshot. The plugin depends on the first compliance_core release that ships the base class, and `depends_on` and the dependency floor rise to it.

The collector is scheduled by a `Schedule` node with cron `0 * * * *` (hourly, UTC) that targets its `Collector` node; the Schedule is seeded by the playground, not by this plugin, because the cadence is a demo decision (`spec-tap-cares-scheduler.md`).

#### Development

This is the first collector of the "run a Search on a schedule and keep the result" pattern. It is deliberately a subclass of a few lines: the pattern is reused for other reports before the demo, each as another subclass in the plugin that owns the report. Collectors cannot yet carry per-instance configuration, so the Search is named in code; when they can, the id moves to data.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-fedramp-20x-vdr-coverage-snapshot-1 | Subclass Of The Base | Implemented | `CoverageSnapshotCollector` subclasses `SearchSnapshotCollector`, sets `SOURCE` to `fedramp_20x_vdr` and `SEARCH_ENTITY_IDS` to the one id above, and defines no `run()` of its own. | |
| req-fedramp-20x-vdr-coverage-snapshot-2 | Registered | Implemented | `coverage_snapshot` is registered under scope `fedramp_20x_vdr` at `ready()`, with a name and a description, and reconciles to one `Collector` node. | |
| req-fedramp-20x-vdr-coverage-snapshot-3 | One Snapshot Per Run | Implemented | On a grid holding that Search, one run writes one `compliance_search_snapshot` with `source` `fedramp_20x_vdr` and an edge `CAPTURES_SEARCH` to the Search, and a second run writes a second snapshot, not a replacement. | |
| req-fedramp-20x-vdr-coverage-snapshot-4 | Missing Search Fails Clearly | Implemented | On a grid without the Search the run fails with an error naming the id and writes nothing. | |
| req-fedramp-20x-vdr-coverage-snapshot-5 | Same Id As The Seed | Implemented | The id in the subclass equals the entity id the playground's seed gives the Search; a test in this plugin pins the id, which shows a change made here. | The pin is one-sided: the playground is a separate repository, so a change to its seed is not seen by this test. Drift there is caught by the hourly run failing with the id named (criterion 4), and the playground's own tests should pin the same literal, which is that repository's requirement to record, not this one's. |
| req-fedramp-20x-vdr-coverage-snapshot-6 | Dependency Floor | Implemented | `depends_on` for `compliance_core` and the dependency floor name the first release that ships `SearchSnapshotCollector`. | |

### Finding Reach
----
RID: `req-fedramp-20x-vdr-reach`

Status: `Implemented`

A method that scores a finding by what its asset needs has to know which asset the finding belongs to. This requirement ships that answer once, so every method plugin (the first is `stackarmor_vdr`) reuses it and none re-derives it. It names the owner of each open finding and the programs involved, and ships the one reduction every method with a confidentiality, integrity and availability requirement (CR, IR, AR) needs. It reads no profile and scores nothing: what a program needs is the method's own stamp, held by the method plugin, so adding a method changes no node or edge that describes the system (ruled by George, 2026-10-21).

The unit is one **finding on one owner**. A finding is already one vulnerability on one component of one image, so the reach merges nothing across components: a package on two programs is two rows (ruled by George, 2026-10-20).

**The ownership rule.** A package the grid can tie to a program belongs to that program. Everything else belongs to the container, with all of the container's programs involved. Nothing the grid cannot tie to a program is ever treated as not in use (ruled by George, 2026-10-21): the default maximises, and only added evidence, an edge, lowers it.

#### Implementation

**Owner by program.** A package is shared by every host that installs it (a package is keyed by ecosystem, name and version), so ownership is decided per container: for each container whose image host installs the finding's package, a program owns the package only if that container runs the program (through `RUNS_PROGRAM`, followed program to program) and the package is reachable from the program's root package. The root is the target of the program's `RUNS_PACKAGE` edge (`req-computing-core-program-package`, released in `computing_core` 0.10.2); the rest is the closure along `REQUIRES_PACKAGE`, followed to any depth. A program with several roots owns the union. A package owned by two programs gives two rows. Read 2026-10-20 in the corpus `tap-web` SBOM: the closure from `tap` is 43 pypi packages, and no pypi package depends on an apk package, so a program's closure never includes system packages.

**Owner by container.** A package outside every program's closure belongs to each container whose image host installs it: the path is `<container> RUNS_IMAGE <host>` and `<host> INSTALLS_PACKAGE <package>`. The container's programs are the targets of `RUNS_PROGRAM` from the container, followed through `RUNS_PROGRAM` from a program to a program (a container runs gunicorn, and gunicorn runs tap-web). The programs an operating system holds (`req-computing-core-runtime-edges-4`) are not the container's programs for this purpose: they carry no profile by nature, so counting them would make every container High.

**A library.** A finding on a library belongs to the programs that `LOADS_LIBRARY` it, one row each. A library no program loads has no container route in the grid (the vocabulary has no host-to-library edge) and yields one row with no owner and no programs, so the gap shows. A package's `SHIPS_LIBRARY` is not followed in this version.

**The row.** `finding_id`, `vuln_id`, `component`, `component_id` (the carrier node, so two components of one name stay two rows), `owner_kind` (`program`, `container` or `none`), `owner_id`, `owner`, `container_id` and `container` (the container whose image host installs the package, carried even when the owner is a program, because a package is shared across hosts and the pair of owner and container is what makes a row unique; null for `none`), and `programs`, the list of `{id, name}` of every program involved (the owner alone for a program, the container's programs for a container, empty for `none`). Open findings with a `CONCERNS_COMPLIANCE_VULNERABILITY` edge only, the set the VDR-max collector covers.

**The reduction.** `reduce_profiles(profiles)` in `tap_plugin/fedramp_20x_vdr/levels.py` takes a list of `(cr, ir, ar)` triples, each value `low`, `medium` or `high` or `None`, and returns one triple: per objective, the highest value, in the order low, medium, high. A `None`, and an empty list, count as high: an unclassified program raises the result, the fail-safe of the stair-step. The method reads each program's profile from its own stamp and calls the reducer; a method with another profile shape ignores it.

**For method plugins.** The reach is a public function, `tap_plugin.fedramp_20x_vdr.searches.reach.reach_rows(inputs, *, db_alias)`, and a `module` Search runner over it. A method plugin imports the function, so the two plugins read the grid once and agree on the owner. Both read through `tap_grid.gryphon.read_scope` with the caller's `db_alias`.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-fedramp-20x-vdr-reach-1 | One Row Per Finding And Owner | Implemented | A finding owned by two programs yields two rows; nothing is merged across programs, containers or components. | Ruled by George, 2026-10-20. |
| req-fedramp-20x-vdr-reach-2 | A Program Owns Its Closure | Implemented | In a container that installs the package and runs the program, a package reachable from the program's `RUNS_PACKAGE` target along `REQUIRES_PACKAGE`, at any depth, belongs to that program; a program with two roots owns both closures. A program that another container runs does not claim the package in this one; there the package falls to the container (`reach-3`). | Drawn for the seed in the playground; the parser draws none. |
| req-fedramp-20x-vdr-reach-3 | The Rest Belongs To The Container | Implemented | A package outside every closure, installed by an image host that a container runs, yields a row owned by that container, with the container's programs involved. | Ruled by George, 2026-10-21. |
| req-fedramp-20x-vdr-reach-4 | Unmarked Is Never Not In Use | Implemented | No row is dropped because a package has no program edge; only a program edge moves a package from the container to its program. | The stair-step rule. |
| req-fedramp-20x-vdr-reach-5 | Operating-System Programs Do Not Count | Implemented | A program held by an operating system through `RUNS_PROGRAM` is not one of a container's programs. | Otherwise every container would be High. |
| req-fedramp-20x-vdr-reach-6 | A Library Follows Its Loaders | Implemented | A finding on a library yields a row per program that loads it; a library no program loads yields one row, `owner_kind` `none`, with no programs. | |
| req-fedramp-20x-vdr-reach-7 | Programs Are Returned | Implemented | Every row carries the full list of programs involved, so a method can read a profile for each and reduce them. | |
| req-fedramp-20x-vdr-reach-8 | The Reduction Fails Safe | Implemented | `reduce_profiles` returns the per-objective maximum in the order low, medium, high, and a `None` entry or an empty list counts as high. | A pure function. |
| req-fedramp-20x-vdr-reach-9 | Open Linked Findings Only | Implemented | A resolved finding, or one with no vulnerability edge, yields no row. | The set of `req-fedramp-20x-vdr-collector-1`. |
| req-fedramp-20x-vdr-reach-10 | No Profile In The Base | Implemented | The plugin reads no stamp, dimension or catalog and ships no profile node, archetype or asset dimension; it adds nothing to a node or edge that describes the system. | Ruled by George, 2026-10-21: a method's stamp lives in the method's plugin. |
| req-fedramp-20x-vdr-reach-11 | Nothing Is Stored | Implemented | The runner writes no node or edge, and nothing the plugin ships gains a field for an owner. | `req-fedramp-20x-vdr-effective-1`. |
| req-fedramp-20x-vdr-reach-12 | Read Rules | Implemented | The runner reads through `tap_grid.gryphon.read_scope` with the caller's `db_alias`, and a tombstoned node contributes nothing. | As `dimension-coverage` in `compliance_core`. |
| req-fedramp-20x-vdr-reach-13 | Importable And Keyed | Implemented | `reach_rows` is importable and the runner is registered as `tap_plugin.fedramp_20x_vdr.searches.reach:vdr-reach`. | The instance's Search pins this literal. |
| req-fedramp-20x-vdr-reach-15 | Container Is Carried | Implemented | Every row carries `container_id` and `container`, including a row whose owner is a program, so one finding on one package in two containers is two rows even when the same program owns it in both; a row with `owner_kind` `none` carries them null. | The uniqueness of 'one row per finding per owner' (`reach-1`) rests on the pair. |
| req-fedramp-20x-vdr-reach-14 | Dependency Floor | Implemented | `depends_on` and the dependency floor name `computing_core` 0.10.2, the first release that ships `RUNS_PACKAGE`. | |

### PAIN Levels And Deadlines
----
RID: `req-fedramp-20x-vdr-pain`

Status: `Implemented`

FedRAMP publishes the PAIN vocabulary (N1 to N5) and the remediation matrix, and not the function from a finding to an N-level. This requirement ships everything about PAIN that a method does not decide: the ordered levels, the exposure column, and the deadline lookup. A method plugin supplies only the level (`stackarmor_vdr` is the first). Another evaluation system, with another way to reach an N-level, reuses all of this.

#### Implementation

**The pure module.** `tap_plugin/fedramp_20x_vdr/levels.py`, Django-free, defines the levels `N1` to `N5` in order, the exposure column from a likely-exploitable flag and an internet-reachable flag (`lev_irv` when both are true, `lev_nirv` when likely exploitable and not reachable, `nlev` when not likely exploitable), and the fail-safe `reduce_profiles` of `req-fedramp-20x-vdr-reach`.

**Reachability.** Internet reachable (IRV) is read from the finding's evaluation of one scheme (an input, default `max`; `req-fedramp-20x-vdr-effective-8`) through the rule of `req-fedramp-20x-vdr-effective-6`: an unset or unsupported factor, or a finding with no evaluation of that scheme, reads as true, and only an evidence-backed false reads as false. Nothing here computes reachability.

**Backed factors.** A method that lets evidence override its own signals (the first, `stackarmor_vdr`, lets an evidence-backed `likely_exploitable` override KEV and EPSS, and does not let a null or unbacked one do so) needs the backed value, not the effective one. The plugin therefore exposes `tap_plugin.fedramp_20x_vdr.evaluations.backed_factors(finding_ids, *, scheme="max", db_alias)`, returning for each finding and each of `likely_exploitable` and `internet_reachable` the value `true`, `false` or `None`, where `None` means no evidence backs a value (no evaluation of that scheme, a null factor, or an unbacked one). The effective value of `req-fedramp-20x-vdr-effective` is that value with `None` read as true.

**The deadline.** `tap_plugin/fedramp_20x_vdr/deadlines.py` exposes `deadline_hours(fedramp_class, pain, column, *, db_alias)`, which returns the `hours` of the `vdr_timeframe` row for the `VDR-TFR-PVR` rule, the class, the level and the column, and `None` for N1, for which FedRAMP publishes no timeframe (`req-fedramp-20x-vdr-low-pain`). The class defaults to `d` (`req-fedramp-20x-vdr-effective-3`). It returns hours, not dates: the clock anchor belongs to the deadlines requirement.

**The contract for a method.** A method plugin returns, for each row of the reach, an N-level; it then calls `deadline_hours` and prints the row. It stores nothing, and `vdr_evaluation.pain` stays refused (`req-fedramp-20x-vdr-evaluation-6`) until a basis list for lowering PAIN exists.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-fedramp-20x-vdr-pain-1 | Pure Levels | Implemented | `levels.py` imports and runs with Django blocked, reads no node and gives the same output for the same input. | |
| req-fedramp-20x-vdr-pain-2 | Ordered Levels | Implemented | The levels N1 to N5 compare in order, and a value outside them is refused. | |
| req-fedramp-20x-vdr-pain-3 | Exposure Column | Implemented | The column is `lev_irv`, `lev_nirv` or `nlev` from the two flags, and a not-likely-exploitable finding is `nlev` whatever its reachability. A `likely_exploitable` that is null, or not backed by evidence, reads as true (`req-fedramp-20x-vdr-effective-1`, `-6`), so unknown never selects `nlev`. | The three columns of the timeframe table. |
| req-fedramp-20x-vdr-pain-4 | Reachability Reads As The Effective Rule | Implemented | IRV is true for an evaluation of the chosen scheme with the factor null or unsupported, or when the finding has none, and false only with an evidence-backed false. | `req-fedramp-20x-vdr-effective-6`. |
| req-fedramp-20x-vdr-pain-5 | Deadline From The Table | Implemented | `deadline_hours` returns the `vdr_timeframe` value for the class, level and column; for class D, N5 and `lev_irv` it is 12. | The 48 seeded `VDR-TFR-PVR` rows equal the memo's Appendix B (read 2026-10-20). |
| req-fedramp-20x-vdr-pain-6 | No Timeframe For N1 | Implemented | `deadline_hours` returns `None` for N1, and a method row shows a null deadline, not zero. | |
| req-fedramp-20x-vdr-pain-7 | Hours, Not Dates | Implemented | The function returns hours; no date arithmetic is done here. | The clock anchor is `req-fedramp-20x-vdr-deadlines`. |
| req-fedramp-20x-vdr-pain-9 | Backed Value Or None | Implemented | `backed_factors` returns `true` or `false` for a factor only when the effective rule's evidence conditions hold, and `None` for a null, unbacked or missing one; the effective value is `None` read as true, so the two never disagree. | Lets a method treat unknown as 'no override' while the base still fails safe. |
| req-fedramp-20x-vdr-pain-8 | A Method Supplies Only The Level | Implemented | The plugin ships no scoring formula, weight or threshold, and `vdr_evaluation.pain` stays refused. | The method plugin owns its math. |

### Deadlines
----
RID: `req-fedramp-20x-vdr-deadlines`

Status: `Implemented`

Three clocks matter and each runs from a different instant. The evaluation deadline (VER-TFR-EVU) runs from detection: the provider should evaluate every vulnerability within 14, 7, 5 or 2 days for class A, B, C or D. The remediation deadline (VDR-TFR-PVR) is stated "from evaluation", and a vulnerability not fully mitigated or remediated within 192 days of evaluation is an accepted vulnerability (VER-TFR-MAV). The clock does not restart when PAIN is lowered (ruled 2026-10-16). The **exact** deadline of an evaluated finding therefore counts from `evaluated_at`, as the rules state, using the timeframe row for that finding's own effective factors; that computation is the partly evaluated Backlog item. The **v0 deadline** is a bound that is never later than the exact one: for every finding, evaluated or not, it counts from `first_detected_at` (the earliest possible anchor, because an evaluation cannot precede detection) and applies the worst-case row.

#### Implementation

Deadlines are shipped as one `module` Search runner, `vdr-deadlines` (`tap_plugin/fedramp_20x_vdr/searches/clocks.py`), whose `view` input selects one of the Searches below; the instance's Search nodes name the runner and set the view. It is computed on read, never stored. Detection time is `first_detected_at` on `compliance_finding` (available since `compliance_core` v0.8.4, Issue# 43 - compliance-core-tap). The runner does the date arithmetic itself, from the open evaluations of one scheme (`scheme`, default `max`), with the class (`fedramp_class`, default `d`, reported as assumed) and the comparison instant (`now`, default the present) as inputs. Gryphon's temporal offset (Issue# 1064 - tap) was verified to work on 2026-10-21 but is not used: the evidence-backed factors the incident Searches need are already one function (`backed_factors`), and a runner keeps both Searches on one code path.

| Search | Meaning |
| --- | --- |
| evaluation overdue | Evaluations that are not **complete** where `first_detected_at` plus the `VER-TFR-EVU` hours for the class is earlier than now. An evaluation is complete only when `evaluated_at` is set and all three factors are set and evidence-backed; a timestamp alone does not complete it. Because `pain` cannot be set in v0, no evaluation is complete in v0, so every evaluation past its evaluation deadline is listed. |
| remediation due | For every open evaluation: `first_detected_at` plus the `VDR-TFR-PVR` hours for the class at N5 and `lev_irv`, with the hours or days remaining. |
| remediation overdue | The same, restricted to those past the deadline. |
| acceptance reached | Open evaluations where `first_detected_at` plus the `VER-TFR-MAV` hours is earlier than now. |
| evaluated | Evaluations with at least one factor set, each marked as showing the worst-case bound (`req-fedramp-20x-vdr-effective`). |
| detection time unobserved | Evaluations whose finding has a `null` `first_detected_at`. No deadline is computed for them and none is defaulted; they are listed. |

Every Search above uses the v0 bound defined in the paragraph before this table, never the exact deadline, and says so in its description. The exact deadline for an evaluated finding belongs to the partly evaluated Backlog item until Gryphon can do the per-finding lookup. An implementation that counts an evaluated finding from `evaluated_at` while still applying the worst-case row is not conformant: that pairing can be later than the exact deadline.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-fedramp-20x-vdr-deadlines-1 | Computed On Read | Implemented | No deadline, overdue flag or remaining-time value is stored on any node. | |
| req-fedramp-20x-vdr-deadlines-2 | Class D Worst Case | Implemented | For a finding detected at time t, the remediation deadline in v0 is t plus 12 hours. | The class D, N5, LEV and IRV cell. |
| req-fedramp-20x-vdr-deadlines-3 | Unobserved Detection Is Listed | Implemented | A finding with null `first_detected_at` appears in the "detection time unobserved" Search and in no overdue Search. | |
| req-fedramp-20x-vdr-deadlines-4 | Bound Stated, Anchor Is Detection | Implemented | Each remediation and acceptance Search counts from `first_detected_at` for every finding, evaluated or not, applies the worst-case row, and its description says it is a bound. | Anchoring an evaluated finding on `evaluated_at` with the worst-case row is non-conformant. |
| req-fedramp-20x-vdr-deadlines-6 | A Timestamp Does Not Complete An Evaluation | Implemented | An evaluation with `evaluated_at` set but a factor null, unsupported or (in v0) `pain` unset still appears in the evaluation-overdue Search once past its evaluation deadline. | Closes the timestamp-only bypass found in review. |
| req-fedramp-20x-vdr-deadlines-5 | Dependencies Landed | Implemented | `first_detected_at` exists on `compliance_finding` and the runner does the date arithmetic, so the Searches ship. | Issue# 43 - compliance-core-tap (v0.8.4). The runner is registered as `tap_plugin.fedramp_20x_vdr.searches.clocks:vdr-deadlines`. |

### Reportable Incidents
----
RID: `req-fedramp-20x-vdr-incidents`

Status: `Implemented`

FedRAMP lets a provider treat certain vulnerabilities as reportable incidents until they are partly mitigated. Under VER-TFR-IRI an internet-reachable, likely exploitable vulnerability with PAIN above N3 is one; under VER-TFR-NRI a likely exploitable vulnerability that is not internet-reachable at N5 is one. The first is stated as "SHOULD" for classes C and D and "MAY" for A and B; the second is "SHOULD" for class D and "MAY" otherwise. Under the worst case every finding in the cohort is a reportable incident at class D, and the Search shows that.

#### Implementation

Two Searches, the `view` values `internet_reachable` and `non_internet_reachable` of one `module` runner, `vdr-incidents` (`searches/clocks.py`), over **every** open evaluation of one scheme, taking the same class input as the deadlines. Neither needs a timeframe row, so the partly evaluated case is computed exactly: a factor reads as unset (null) unless evidence backs it. The first returns evaluations whose effective factors are likely exploitable (`likely_exploitable` null or true), internet-reachable (`internet_reachable` null or true) and PAIN above N3 (`pain` null or in N4, N5). The second returns those likely exploitable, with `internet_reachable` false, and effective PAIN N5 (`pain` null or N5). Under the all-null worst case only the first returns rows; the second returns rows once an `internet_reachable` of false is recorded. Each Search states whether the class makes the rule a SHOULD or a MAY.

**Unsupported factors read as null.** The incident Searches count a factor as set only when evidence backs it (`req-fedramp-20x-vdr-effective`, "A factor counts as set only when evidence backs it"). An unsupported value therefore cannot take an evaluation out of an incident Search; it stays in as if the factor were null, and `req-fedramp-20x-vdr-evidence-3` additionally reports it. This guarantee is a ship condition, not a best effort: each incident Search is one runner that applies it (`req-fedramp-20x-vdr-incidents-6`). In v0 a PAIN value cannot be evidence-backed, so it always reads as N5 and the N3 transition out of the first Search is deferred with PAIN evidence (`req-fedramp-20x-vdr-low-pain` and the PAIN basis list).

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-fedramp-20x-vdr-incidents-1 | Worst Case Is An Incident | Implemented | With the default class, every all-null evaluation appears in the internet-reachable incident Search. | |
| req-fedramp-20x-vdr-incidents-2 | Threshold Is Above N3 | Implemented | The internet-reachable Search requires effective PAIN greater than N3, and the other requires N5. | |
| req-fedramp-20x-vdr-incidents-3 | Modal Stated | Implemented | Each Search description says whether the rule is a SHOULD or a MAY for the class in use. | |
| req-fedramp-20x-vdr-incidents-4 | Partly Evaluated Is Computed | Implemented | An evaluation with an evidence-backed factor is placed by its effective values: `likely_exploitable` of false removes it from both Searches; `internet_reachable` of false moves a likely exploitable N5 from the first Search into the second. | PAIN transitions wait for a PAIN basis list. |
| req-fedramp-20x-vdr-incidents-5 | Unsupported Factor Reads As Null | Implemented | An evaluation with `likely_exploitable` of false, or `internet_reachable` of false, and no evidence edge for that factor still appears in the first Search. A `pain` value always reads as N5 in v0. | Verified by a test that writes the value without the edge. |
| req-fedramp-20x-vdr-incidents-6 | One Search Applies The Test | Implemented | Each incident Search is a single Search that applies the evidence test itself, through `backed_factors`; no page has to show two Searches to get the right answer. | Whether Gryphon can express the test in one query was not established; the runner is the single Search instead (decided 2026-10-21 so the Searches are ready for the demo). A pair of Searches that depends on a page showing both is not conformant. |

### v0 Non-Goals
----
RID: `req-fedramp-20x-vdr-nongoals`

Status: `Proposed`

The plugin does not, in v0:

- ship pages, panels or a layout; the Searches are the surface other pages read;
- mint findings, vulnerabilities, scanners or scan runs, or store a detection time (compliance_core owns them; Issue# 43 - compliance-core-tap);
- store a date: the deadline Searches compute dates on read in the runner, and no node holds one;
- evaluate a finding that has no vulnerability edge, or a resolved one;
- compute the exact deadline for an evaluation with any factor set; v0 shows the worst-case bound (`req-fedramp-20x-vdr-partial`);
- store PAIN, an owner, an effective profile or a roll-up: the reach computes on read (`req-fedramp-20x-vdr-reach`) and a method plugin computes the level;
- score a finding: the formula, weights and thresholds belong to a method plugin such as `stackarmor_vdr`;
- invent a timeframe for PAIN N0 or N1 (`req-fedramp-20x-vdr-low-pain`);
- represent the system's class as anything but the default input (`req-fedramp-20x-vdr-class`);
- schedule or seed the coverage snapshot's Search or Schedule (the playground owns both; `req-fedramp-20x-vdr-coverage-snapshot`);
- produce the per-period VDR report, grouping, false-positive or accepted-vulnerability records, detection cadence, or failures as vulnerabilities (the Backlog rows above).

## Model catalog

Design-time; superseded by the manifest once the owning requirement is `Implemented`.

| Model | Entity type | Category | Rationale |
| --- | --- | --- | --- |
| `vdr_evaluation` | `fedramp_20x_vdr__vdr_evaluation` | Judgement | A judgement by a party at a time, one per finding per scheme, kept apart from the scanner's observation. |
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
