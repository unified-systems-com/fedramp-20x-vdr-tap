# FedRAMP 20x VDR Plugin Specification

**`fedramp_20x_vdr` evaluates every vulnerability finding under FedRAMP's Vulnerability Detection and Response rules, computes its deadlines, and produces the FedRAMP vulnerability report documents from what the grid holds, whichever evaluation method rates the findings. It starts from the worst case for every factor (a likely exploitable, internet-reachable vulnerability at PAIN N5) and lowers a factor only when evidence is attached, so an unevaluated finding is visible as such and is never mistaken for a safe one.**

## Plugin Identity

| Row | Value |
| --- | --- |
| Slug | `fedramp_20x_vdr` |
| Display name | `TAP FedRAMP 20x VDR` |
| Description | Per-finding FedRAMP 20x Vulnerability Detection and Response evaluation (LEV, IRV, PAIN), the remediation timeframe tables as data, the deadlines they imply, and the FedRAMP VER report documents. |
| Kind | Leaf plugin. It consumes `compliance_core` (findings, vulnerabilities, evidence) and is consumed by the pages and products that show vulnerability posture, by method plugins that rate findings, and by plugins that deliver its report documents (the first planned is `regscale`). |

Default dimensions, one key for every node and edge the plugin ships:

| Key | Value | Why |
| --- | --- | --- |
| `fedramp.rule` | `vdr` | Names the FedRAMP rule family the object belongs to, so a filter can scope to VDR without naming a type. A future rule family from the same regime (the key-security-indicator family) takes its own value. The value is not the entity type. |
| `vdr.scheme` | the evaluation's `scheme` | Stamped on every `vdr_evaluation` and its `EVALUATES_COMPLIANCE_FINDING` edge, from the node's `scheme` column, so a filter or page can scope to one algorithm (`max`, or another scheme's name) without reading the column. It is a copy for filtering, not the identity: the identity is the column (`req-fedramp-20x-vdr-evaluation-7`). Not stamped on timeframe rows. |

## Philosophy

FedRAMP's rules ask a provider to evaluate each detected vulnerability and then to act on a clock that depends on the answer. Most operators loading a new system have only part of what a full evaluation needs, often just a count of vulnerabilities per host. The plugin therefore works as a stair-step, a proof by contradiction. Step 0, "VDR-max", presumes the worst case for every finding and makes the mechanics, tables and pages work on the grid that already exists. Later steps attach evidence that contradicts a presumption, and each contradiction lowers one factor for one finding. Adding evidence never changes the model; it only fills fields that were null.

**Null is the worst case.** An unset factor is treated as the worst case, and that is actionable: it appears as work to do. A factor leaves null, in the **effective** sense that every Search uses, only through an evidence edge. The stored fields are raw inputs, not answers: a concrete value without evidence can be stored (an edge cannot be checked when its node is written), and it is read as null by every shipped Search, so a page or Search that reads `vdr_evaluation` factors directly instead of through the shipped Searches is non-conformant (`req-fedramp-20x-vdr-effective-7`). The worst-case value is computed where it is read and is never written into the factor, so a reader cannot mistake "no one has looked" for "someone concluded N5". This is the grid's three-state rule (`req-grid-node-observation`): null is unobserved, an empty value is observed-empty, and a concrete value is an observation.

**What the plugin deliberately does not do.** It does not judge anything about a vulnerability's published facts (CVSS, EPSS, KEV, SSVC live on `compliance_vulnerability` in compliance_core). It is not a scanner and mints no findings. Its only pages are the three report pages, built from core panels. It does not deliver its documents anywhere: an emitter or a consuming plugin does that.

**Provenance markers.**
- *Observed:* the FedRAMP pages `reference/vulnerability-detection-and-response`, `reference/vulnerability-evaluation-and-reporting` and `definitions` at `https://www.fedramp.gov/2026/`, read as raw HTML on 2026-10-16 (fetched with curl, tags stripped), including the four timeframe tables and the N0 to N5 definitions (changelog 2026-10-05). The `compliance_core` v0.7.1 spec and models, read on 2026-10-16.
- *Documented:* the CycloneDX 1.6 JSON schema for the vulnerability analysis states and justifications, read from the CycloneDX repository's master branch on 2026-10-16.
- *Observed:* the FedRAMP CR26 JSON Schemas of 2026-06-24 (the vulnerability detail report, accepted vulnerability info and historical VER activity schemas at `$schemaVersion` 0.1.1, the common definitions at 0.4.2), the consolidated rules file version 2026.11.02.01, and the VDR/VER migration FAQ, read from local copies on 2026-11-24. The method plugins stackarmor-vdr-tap (`a5afb0c`) and sam-aydlette/aydlette-vdr-tap (`97b1ca7`), and the coalfire-vdr-tap README, read on 2026-11-24. Core's file store, HTML panel, table panel and plugin API router, read in the tap tree on 2026-11-24.
- *Designed:* everything else in this document. Nothing here has been built or run.

## Goals

| # | Name | Description |
| --- | --- | --- |
| 1 | Worst Case By Default | Every finding has an evaluation whose unset factors read as the worst case. |
| 2 | Evidence Lowers | A factor reads as anything but the worst case only with an evidence edge naming the factor and its basis. |
| 3 | Tables As Data | FedRAMP's timeframe tables are seeded rows that cite their rule, not constants in code. |
| 4 | Computed Deadlines | Deadlines and overdue flags are computed from first detection and the seeded rows, never stored. |
| 5 | Additive Stages | Attaching evidence in a later stage fills fields; it adds no migration and rewrites no node. |
| 6 | One Stored Document | Each report document is generated once, validated against FedRAMP's schema and kept; the page, the download and the API all serve those bytes, and no method's code is imported to make it. |

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
| req-fedramp-20x-vdr-deadlines | [Deadlines](#deadlines) | Implemented | Evaluation deadline, remediation deadline, overdue and acceptance flags as Searches. Needs `first_detected_at` (Issue# 43 - compliance-core-tap, v0.8.4); the runner does the date arithmetic. |
| req-fedramp-20x-vdr-incidents | [Reportable Incidents](#reportable-incidents) | Implemented | The internet-reachable and non-internet-reachable incident rules as Searches. Ship condition: each is one Search that applies the evidence test itself (`-incidents-6`). |
| req-fedramp-20x-vdr-summary | [Summary Counts](#summary-counts) | Implemented | The `vdr-summary` `module` Search runner: the counts of the deadline and incident Searches for one scheme, for cards and charts. |
| req-fedramp-20x-vdr-profile | [Report Profile](#report-profile) | Proposed | The node that declares an offering's FedRAMP ID, package URI, class, reporting start, evaluation scheme and rating method (`RUNS_SEARCH`). |
| req-fedramp-20x-vdr-rating | [Method Rating Contract](#method-rating-contract) | Proposed | The row shape a method's Search returns (`finding_id`, `pain`, `lev`, `irv`, `evaluated_at`), as a JSON Schema; the export imports no method. |
| req-fedramp-20x-vdr-finding-state | [Finding State History](#finding-state-history) | Proposed | `vdr_finding_state`, written when a finding's rating or disposition changes, so reports can state history and reductions. |
| req-fedramp-20x-vdr-report | [Report Documents](#report-documents) | Proposed | `vdr_report`, one per document, the format record of a held file; pinned FedRAMP schemas, validated at generation; periods without gaps. Promoted from Backlog. |
| req-fedramp-20x-vdr-mapping | [Document Field Mapping](#document-field-mapping) | Proposed | Every schema field from grid facts: disposition, accepted (exception or 192 days), false positives, overdue, KEV and CVE, VER-RPT-NID. Absorbs the former Backlog row Accepted Vulnerability Record (VER-RPT-AVI). |
| req-fedramp-20x-vdr-generator | [Report Generator](#report-generator) | Proposed | The `vdr_report` collector: scheduled by the instance, run on demand from Administrivia; three documents per active profile. |
| req-fedramp-20x-vdr-fetch | [Programmatic Fetch](#programmatic-fetch) | Proposed | `list_reports` and `fetch_document`, and the plugin API routes; serve the stored bytes; an emitter's payload source. |
| req-fedramp-20x-vdr-download | [Download Links](#download-links) | Proposed | The `vdr-reports` Search and a table-panel configuration linking to core's file download; no new route or panel type. |
| req-fedramp-20x-vdr-document-markup | [Document Markup Search](#document-markup-search) | Proposed | The `vdr-report-markup` runner: heading and formatted-document markup for core's HTML panel, from the stored document. |
| req-fedramp-20x-vdr-page-vdt | [Vulnerability Detail Report Page](#vulnerability-detail-report-page) | Proposed | Heading, formatted document and download for VER-RPT-VDT. |
| req-fedramp-20x-vdr-page-avi | [Accepted Vulnerability Info Page](#accepted-vulnerability-info-page) | Proposed | Heading, formatted document and download for VER-RPT-AVI. |
| req-fedramp-20x-vdr-page-mrh | [Historical Activity Page](#historical-activity-page) | Proposed | Heading, formatted document, download and fetch address for VER-TFR-MRH. |
| req-fedramp-20x-vdr-nongoals | [v0 Non-Goals](#v0-non-goals) | Proposed | What v0 does not build. |
| req-fedramp-20x-vdr-syntax-colour | [Syntax Colouring](#document-markup-search) | Backlog | Core change in `tap_web`: colour the formatted JSON. The HTML panel's closed class list and element ceiling do not admit it; recommended is a JSON panel type that generates escaped markup itself. |
| req-fedramp-20x-vdr-api-token | [Machine Access To The API](#programmatic-fetch) | Backlog | Core change in `tap_api`: token or service authentication, so a party outside the instance can fetch the historical document (VER-TFR-MRH). |
| req-fedramp-20x-vdr-next-reduction | [Projected Next Reduction](#document-field-mapping) | Backlog | `projectedNextReduction` needs a record of a planned mitigation and its target rating. |
| req-fedramp-20x-vdr-likely-overdue | [Likely Overdue](#document-field-mapping) | Backlog | VER-RPT-VDT item 9's "likely to become an overdue vulnerability"; v0 reports overdue only once past due. |
| req-fedramp-20x-vdr-grouping | [Grouping](#v0-non-goals) | Backlog | Logical groupings of affected resources (VER-EVA-GRV). Until then the report documents carry one record per finding. |
| req-fedramp-20x-vdr-false-positive | [False Positive](#v0-non-goals) | Backlog | Evaluating findings as false positives (VER-EVA-EFP). Reporting a false positive already recorded as a compliance_core exception is `req-fedramp-20x-vdr-mapping`. |
| req-fedramp-20x-vdr-failures | [Failures Are Vulnerabilities](#v0-non-goals) | Backlog | Detection-process failures treated as vulnerabilities (VDR-CSO-FAV). |
| req-fedramp-20x-vdr-cadence | [Detection Cadence](#v0-non-goals) | Backlog | The scan-frequency rules (VDR-TFR-PDD, -PCD, -PSD, -MVX). |
| req-fedramp-20x-vdr-low-pain | [N0 And N1 Timeframes](#v0-non-goals) | Backlog | No published timeframe exists for PAIN N0 or N1; waits on FedRAMP. |
| req-fedramp-20x-vdr-reach-direct | [Direct Reachability](#finding-reach) | Backlog | Computing IRV from the network surface (public routes, listeners, protocol), the direct branch of the reachability model, instead of reading it from the evaluation. |
| req-fedramp-20x-vdr-reach-shipped | [Shipped Libraries](#finding-reach) | Backlog | Following `SHIPS_LIBRARY` from a package to the programs that load a library it ships. |
| req-fedramp-20x-vdr-class | [Class Node](#v0-non-goals) | Backlog | Replaces the v0 default class of the shipped Searches with a node that records the class. The report profile already records it for the export (`req-fedramp-20x-vdr-profile`); this row is pointing the Searches at it. |
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

The classification mapping (`req-compliance-core-dimension-mapping`) says how much of the inventory carries the data classification it should, and an auditor wants that figure over time, not once. This plugin records it. A second derived collector, `coverage_snapshot`, runs the coverage Searches on a schedule and stores each one's rows as a `compliance_search_snapshot` (`req-compliance-core-search-snapshot`). The plugin owns this because the coverage figure is what its VDR work reports against; the Search it records belongs to the demo project and is seeded there.

#### Implementation

`tap_plugin/fedramp_20x_vdr/collectors/coverage_snapshot/collector.py` holds `CoverageSnapshotCollector`, a subclass of `tap_plugin.compliance_core.collectors.search_snapshot.SearchSnapshotCollector` (`req-compliance-core-search-snapshot-collector`) that sets two attributes and nothing else:

| attribute | value |
| --- | --- |
| `SOURCE` | `fedramp_20x_vdr` |
| `SEARCH_ENTITY_IDS` | `("01a15b2f-df3b-7569-bf22-9ead3f816b84", "01a15fdf-61ef-710d-b5d3-e3a7ae238a40")`: the playground's classification-mapping summary Search and its responsibility-coverage summary Search, both `dimension-mapping-summary` |

It is registered in `apps.py` under scope `fedramp_20x_vdr` and key `coverage_snapshot`, beside `vdr_max`, with a name and description. It reads the grid and calls no outside service, so it needs no credential and no call ceiling.

The two Search ids are hard-coded in the subclass for the demo (ruled by George 2026-10-20). Each id is minted once and is the entity id the playground's seed gives that Search (`req-rampart-20x-playground-snapshot-search`, `req-rampart-20x-playground-inventory-coverage`); the two must never differ. If a Search is not on the grid the base class fails the run with an error naming the id and writes nothing, so a deployment without the playground shows a failed run, not a bad snapshot. The plugin depends on the first compliance_core release that ships the base class, and `depends_on` and the dependency floor rise to it.

The collector is scheduled by a `Schedule` node with cron `0 * * * *` (hourly, UTC) that targets its `Collector` node; the Schedule is seeded by the playground, not by this plugin, because the cadence is a demo decision (`spec-tap-cares-scheduler.md`).

#### Development

This is the first collector of the "run a Search on a schedule and keep the result" pattern. It is deliberately a subclass of a few lines: the pattern is reused for other reports before the demo, each as another subclass in the plugin that owns the report. Collectors cannot yet carry per-instance configuration, so the Search is named in code; when they can, the id moves to data.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-fedramp-20x-vdr-coverage-snapshot-1 | Subclass Of The Base | Implemented | `CoverageSnapshotCollector` subclasses `SearchSnapshotCollector`, sets `SOURCE` to `fedramp_20x_vdr` and `SEARCH_ENTITY_IDS` to the two ids above, and defines no `run()` of its own. | |
| req-fedramp-20x-vdr-coverage-snapshot-2 | Registered | Implemented | `coverage_snapshot` is registered under scope `fedramp_20x_vdr` at `ready()`, with a name and a description, and reconciles to one `Collector` node. | |
| req-fedramp-20x-vdr-coverage-snapshot-3 | One Snapshot Per Search Per Run | Implemented | On a grid holding both Searches, one run writes one `compliance_search_snapshot` per Search, each with `source` `fedramp_20x_vdr` and an edge `CAPTURES_SEARCH` to its Search, and a second run writes two more, not replacements. | |
| req-fedramp-20x-vdr-coverage-snapshot-4 | Missing Search Fails Clearly | Implemented | On a grid without the Search the run fails with an error naming the id and writes nothing. | |
| req-fedramp-20x-vdr-coverage-snapshot-5 | Same Ids As The Seed | Implemented | Each id in the subclass equals the entity id the playground's seed gives its Search; a test in this plugin pins the id, which shows a change made here. | The pin is one-sided: the playground is a separate repository, so a change to its seed is not seen by this test. Drift there is caught by the hourly run failing with the id named (criterion 4), and the playground's own tests should pin the same literal, which is that repository's requirement to record, not this one's. |
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
| req-fedramp-20x-vdr-deadlines-7 | One Finding | Implemented | The optional input `entity_id` limits `vdr-deadlines` and `vdr-incidents` to the evaluation of that finding. | Lets a page follow one finding. |
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

### Summary Counts
----
RID: `req-fedramp-20x-vdr-summary`

Status: `Implemented`

A card or a chart needs counts and the deadline Searches return lists. `vdr-summary` (`searches/clocks.py`) counts them with the same code, so a count can never differ from the list it summarises. It stores nothing.

#### Implementation

Inputs: `view` (`counts`, the default, or `by_view`), `now`, `fedramp_class` (default `d`) and `scheme` (default `max`). `counts` returns one row: `evaluations` (the open evaluations of the scheme), `evaluation_overdue`, `remediation_overdue`, `acceptance_reached`, `evaluated`, `detection_unobserved`, `incidents_internet_reachable` and `incidents_non_internet_reachable`. `by_view` returns the same numbers as eight rows of `view`, `label` and `count`. Each count is the row total of the Search of that name.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-fedramp-20x-vdr-summary-1 | Counts Match The Lists | Implemented | Each count equals the number of rows the Search of that name returns for the same inputs. | |
| req-fedramp-20x-vdr-summary-2 | By View | Implemented | `by_view` returns the eight numbers as rows with `view`, `label` and an integer `count`. | |
| req-fedramp-20x-vdr-summary-3 | Zero Is Stated | Implemented | On a grid with no evaluations every count is 0, not missing. | |
| req-fedramp-20x-vdr-summary-4 | Bad Input Refused | Implemented | An unknown input, a `view` other than the two and a class other than a to d are refused with a `ValueError`. | |
| req-fedramp-20x-vdr-summary-5 | Registered, Read Only | Implemented | The runner is registered as `tap_plugin.fedramp_20x_vdr.searches.clocks:vdr-summary` and writes nothing. | |

### Report Profile
----
RID: `req-fedramp-20x-vdr-profile`

Status: `Proposed`

The report documents describe one cloud service offering, under one FedRAMP class, rated by one method. Part of that cannot be derived from the grid: the offering's FedRAMP ID, the address of its Certification Package Overview, its class, the instant reporting began, and which method rates its findings. TAP has no plugin-configuration model and a collector cannot carry per-instance configuration (the Development note of `req-fedramp-20x-vdr-coverage-snapshot`), so these declarations are a node: the report profile. It is what the provider declares about how its offering reports, it has history, and a person can edit it.

Rejected: Search ids hard-coded in a collector subclass, as the coverage snapshot does (a FedRAMP ID and a URI are not code, and one instance may report for two offerings); settings or environment variables (plugin configuration must not live in shared infrastructure, AGENTS.md); Search input defaults (they cannot hold a FedRAMP ID, and a default is a value nobody declared).

#### Implementation

Entity type `fedramp_20x_vdr__vdr_report_profile`. `NATURAL_KEY = ("profile_key",)`. Default dimensions `{"fedramp.rule": "vdr"}`. Seeded by the instance, never by this plugin.

| field | meaning |
| --- | --- |
| `profile_key` | Required, 1 to 64 characters of `[a-z0-9_-]`. The identity, and a path segment of the stored files and the API. |
| `fedramp_id` | Required, 1 to 64 characters of `[A-Za-z0-9._-]`. The FedRAMP ID, or the provider's placeholder until one is assigned (CDS-CSO-FID note). |
| `certification_package_overview_uri` | Required, `format: uri`. Written into every document (the schemas require it). |
| `fedramp_class` | `a` to `d`, or `null`. `null` is unobserved: the export uses `d` and every report it generates records `class_assumed: true`, as the shipped Searches already state an assumed class (`req-fedramp-20x-vdr-effective-3`). |
| `reporting_start` | Required, `format: date-time`. The `from` of the first Vulnerability Detail and Accepted Vulnerability Info period, and the start of the historical document. Never defaulted: a default would invent the start of a period. |
| `evaluation_scheme` | Required, 1 to 64 characters. The `vdr_evaluation` scheme that defines which findings the documents cover and whose evidence-backed factors are the fallback for LEV and IRV: `max` for the VDR-max stage, or a method's own scheme (for example `aydlette`). |
| `method_inputs` | JSON object, default `{}`. Passed verbatim to the method Search as its inputs; the Search validates them against its own input schema when it runs. Lossless configuration for another component, so a blob rather than columns. |
| `active` | Boolean, default `true`. An inactive profile is not generated. |

`RUNS_SEARCH` runs from a `vdr_report_profile` to a tap_grid `search` node: the Search that rates the profile's findings under the contract of `req-fedramp-20x-vdr-rating`. Plain identity, default dimension. At most one per profile; none is allowed and means no method rates this offering yet.

The class here is read by the export only. The shipped deadline, incident and summary Searches keep their `fedramp_class` input until `req-fedramp-20x-vdr-class` (Backlog) points them at a node.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-fedramp-20x-vdr-profile-1 | Keyed By Profile Key | Proposed | `vdr_report_profile` declares `NATURAL_KEY = ("profile_key",)`; a second write with the same key is the same node. | |
| req-fedramp-20x-vdr-profile-2 | Declarations Required | Proposed | A write without `fedramp_id`, `certification_package_overview_uri`, `reporting_start` or `evaluation_scheme`, or with any of them outside its pattern or format, is refused. | |
| req-fedramp-20x-vdr-profile-3 | Class Assumed Visibly | Proposed | With `fedramp_class` null, the generator uses `d` and every report it writes for the profile has `class_assumed` true; with a class set, `class_assumed` is false. | |
| req-fedramp-20x-vdr-profile-4 | At Most One Method | Proposed | A profile with two `RUNS_SEARCH` edges is reported by a check, and the generator fails that profile, naming both Searches. | |
| req-fedramp-20x-vdr-profile-5 | No Method Is Allowed | Proposed | A profile with no `RUNS_SEARCH` edge generates valid documents in which no record carries a rating (`req-fedramp-20x-vdr-mapping-3`). | The VDR-max stage can report before any method is installed. |

### Method Rating Contract
----
RID: `req-fedramp-20x-vdr-rating`

Status: `Proposed`

The export must work with any VDR evaluation method and import none. Every method so far already publishes its ratings as a `module` Search (`stackarmor-pain`, `aydlette-pain`), so the contract is the shape of a row the export reads from that Search, and nothing more. It is declared as a JSON Schema in this plugin, so a method author checks conformance against a file, never against export code.

Rejected: importing a method's Python (couples the export to each method); having methods write PAIN to `vdr_evaluation` (refused in v0, `req-fedramp-20x-vdr-evaluation-6`, and every method computes on read); a per-method column map on the profile (both methods read on 2026-11-24 already use the contract's names, so the map would be configuration with no user).

#### Implementation

`data/method_rows.schema.json`, with a `description` at the top and on every property. Columns the export reads; every other column is ignored:

| column | meaning |
| --- | --- |
| `finding_id` | Required. The entity id of the `compliance_finding` rated. |
| `pain` | `N0` to `N5`, or `null` (the method could not rate this row). |
| `lev` | Boolean or `null`. Likely exploitable. |
| `irv` | Boolean or `null`. Internet reachable. |
| `evaluated_at` | Optional, `format: date-time` or `null`. When the method's evaluation was completed, if the method knows. |

**Several rows for one finding** (a finding on two owners in `stackarmor-pain`, a finding naming two CVEs in `aydlette-pain`) are reduced fail-safe: `pain` is the highest level, or `null` if any row is `null`, because an unrated part could be the worst; `lev` and `irv` are true if any row is true, false only if every row is false, and `null` otherwise; `evaluated_at` is the latest, or `null` if any row lacks one.

**Three states.** A `null` rating stays unknown in the documents: the field is omitted and the record says so (`req-fedramp-20x-vdr-mapping`). It is never written as N5. The deadline still reads it as N5 (`req-fedramp-20x-vdr-effective`), and the overdue explanation says that it did.

**Independence, tested against two methods as read on 2026-11-24.**

| Method | Rows | Fit |
| --- | --- | --- |
| `stackarmor-pain` (stackarmor-vdr-tap `a5afb0c`) | One per finding, owner and container; `finding_id`, `pain` N1 to N5, `lev`, `irv`; no `evaluated_at`. | Conforms unchanged. |
| `aydlette-pain` (sam-aydlette/aydlette-vdr-tap `97b1ca7`) | One per finding and CVE, every open finding including those with no CVE; `finding_id`, `pain` N0 to N5, `lev`, `irv`, plus clock, gates, dispositions and bases, which the export ignores. Its `fedramp_class` input is required. | Conforms unchanged; the profile passes `fedramp_class` (and a `max_results` large enough for the cohort) in `method_inputs`, and sets `evaluation_scheme` to `aydlette`, the scheme its bridge collector writes. |
| `coalfire_vdr` (README only, no code) | Holds a finding at N3 when an input is missing, so returns a level for every row. | Conforms if its Search returns the four columns. |

The PAIN a method returns is that method's output, not an evaluation: `vdr_evaluation.pain` stays refused.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-fedramp-20x-vdr-rating-1 | Rows Validated | Proposed | A row that does not validate against `data/method_rows.schema.json` fails that profile's generation with an error naming the Search, the row and the column; nothing is written for the profile. | |
| req-fedramp-20x-vdr-rating-2 | No Method Imported | Proposed | No module of this plugin imports a method plugin; a test lists the plugin's imports and finds only TAP core, `compliance_core`, `computing_core` and the standard library. | |
| req-fedramp-20x-vdr-rating-3 | Reduction Fails Safe | Proposed | Two rows for one finding with `N3` and `N4` give `N4`; with `N3` and `null` give `null`; `lev` of `false` and `null` gives `null`; `false` and `false` gives `false`. | |
| req-fedramp-20x-vdr-rating-4 | Two Methods Unchanged | Proposed | Fixtures in the row shapes of `stackarmor-pain` and `aydlette-pain` as read on 2026-11-24 each produce three valid documents with no change to export code. | The independence test. |
| req-fedramp-20x-vdr-rating-5 | The Whole Result | Proposed | The generator reads every page of the Search's result; a result the runner reports as truncated fails the profile. | A silently partial result would drop ratings. |
| req-fedramp-20x-vdr-rating-6 | Strangers Are Counted | Proposed | Rows whose `finding_id` is outside the profile's findings are counted in a warning and reported nowhere. | |

### Finding State History
----
RID: `req-fedramp-20x-vdr-finding-state`

Status: `Proposed`

The Vulnerability Detail Report asks for the historical and current N-rating and the time and rating of each reduction (VER-RPT-VDT items 6 and 7), and the historical document asks for history (VER-TFR-MRH). Methods compute on read and keep none: Aydlette's own "rating changes are appended" is Backlog for that reason (`req-aydlette-vdr-pain-9`). So each time the generator runs it records the state of each finding under each profile, as a node, and only when that state changed.

Rejected: reading node history (history is an audit trail, not a Search read path); a full snapshot node per finding per run (grows with findings times runs and records nothing a change point does not); writing PAIN onto `vdr_evaluation` (refused in v0); re-reading earlier stored documents (a document is an output, not a record to compute from).

#### Implementation

Entity type `fedramp_20x_vdr__vdr_finding_state`. `NATURAL_KEY = ("profile_key", "finding_source", "finding_source_key", "observed_at")`. `EVENT_TIME` is `observed_at`. Default dimensions `{"fedramp.rule": "vdr"}`.

| field | meaning |
| --- | --- |
| `profile_key` | The profile this state was recorded under. |
| `finding_source`, `finding_source_key` | The finding's `source` and `source_key`, verbatim. |
| `observed_at` | The generation instant at which the state was first seen. |
| `pain` | `N0` to `N5`, or `null`: the reduced rating of `req-fedramp-20x-vdr-rating`. |
| `likely_exploitable`, `internet_reachable` | Boolean or `null`, as reported (`req-fedramp-20x-vdr-mapping`). |
| `disposition` | `active`, `accepted`, `false-positive`, `remediated`, `partially-mitigated` or `fully-mitigated` (`req-fedramp-20x-vdr-mapping`). |
| `search_id` | The `search` node that produced the rating, or `null` when the profile has no method. |

`TRACKS_COMPLIANCE_FINDING` runs from a `vdr_finding_state` to its `compliance_finding`. Plain identity, default dimension.

A state is written when the finding has none under the profile, or when `pain`, `likely_exploitable`, `internet_reachable` or `disposition` differs from its latest. A state is never updated or deleted, and the generator never sends a key that exists (a GRIFT node sent under an existing key replaces the row, `req-fedramp-20x-vdr-collector`).

**What the times mean.** `observed_at` is when the generator saw the state, so a reduction is reported no earlier than it happened and at most one generator interval later. The reports say so on the history page (`req-fedramp-20x-vdr-page-mrh`).

**What it is not.** It is a record of what the configured method returned and when, not an evaluation. No deadline, incident or summary Search reads it, so `req-fedramp-20x-vdr-effective-7` is unaffected. It is the one place this plugin writes a PAIN value.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-fedramp-20x-vdr-finding-state-1 | First Run Records Every Finding | Proposed | After the first run of a profile, every finding in its documents has exactly one state, with an edge to the finding. | |
| req-fedramp-20x-vdr-finding-state-2 | Unchanged Is Not Rewritten | Proposed | A second run with no change in rating or disposition writes no state. | |
| req-fedramp-20x-vdr-finding-state-3 | A Change Is A New Node | Proposed | A rating that moves from N4 to N3 between runs writes one new state; the earlier state is unchanged. | |
| req-fedramp-20x-vdr-finding-state-4 | Append Only | Proposed | No code path sends a `vdr_finding_state` whose key exists, or deletes one. | |
| req-fedramp-20x-vdr-finding-state-5 | Not A Rules Input | Proposed | No shipped deadline, incident or summary Search reads `vdr_finding_state`. | |

### Report Documents
----
RID: `req-fedramp-20x-vdr-report`

Status: `Proposed`

Each generated document is one `vdr_report` node and one file held in TAP's file store (`specs/spec-tap-file-store.md` in core). The node is the file's format record (`req-tap-files-format-record`): what the bytes are, for which profile and period, against which schema. The three kinds are the FedRAMP schemas of 2026-06-24: the Vulnerability Detail Report (`vdt`, VER-RPT-VDT and VER-RPT-PER), Accepted Vulnerability Info (`avi`, VER-RPT-AVI) and Historical VER Activity (`mrh`, VER-TFR-MRH).

Rejected: the JSON body in a field of the node (a whole document read whole belongs in the one store core keeps for documents, which also gives the digest, the download route and kept versions); one node per period holding three bodies (a format record describes one file).

#### Implementation

Entity type `fedramp_20x_vdr__vdr_report`. `NATURAL_KEY = ("profile_key", "kind", "generated_at")`. `EVENT_TIME` is `generated_at`. Default dimensions `{"fedramp.rule": "vdr"}`.

| field | meaning |
| --- | --- |
| `profile_key`, `kind` | The profile, and `vdt`, `avi` or `mrh`. |
| `generated_at` | The generation instant, shared by the three documents of one run. |
| `period_from`, `period_to` | For `vdt` and `avi`, the document's `reportPeriod`. For `mrh`, the span it covers: the profile's `reporting_start` to `generated_at`. `period_to` always equals `generated_at`. |
| `schema_id`, `schema_version` | The document schema's `$id` and `$schemaVersion`. |
| `fedramp_id`, `fedramp_class`, `class_assumed`, `evaluation_scheme`, `method_search_id` | Copied from the profile at generation, because a report states what it was generated with and the profile can change later. `method_search_id` is `null` when the profile has no method. |
| `record_count` | The number of records in the document. |

`APPLIES_REPORT_PROFILE` runs from a `vdr_report` to its profile. `FOLLOWS_VDR_REPORT` runs from a `vdr_report` to the previous report of the same profile and kind; the first has none. Both plain identity, default dimension.

**The body.** A new `tap_file` per document, held through core's `hold_file`, at `fedramp_20x_vdr/<profile_key>/<kind>/<fedramp_id>-<kind>-<generated_at as YYYYMMDDTHHMMSSZ>.json` with media type `application/json`: a new file each time, never a new version of one (`req-tap-files-hold`, "What is normally a new file"). The plugin then writes `FILE_CONTENTS` from the `tap_file` to the `vdr_report`, carrying the file's `sha256`. The manifest declares `[file_store] required = true`.

**Periods without gaps (VER-RPT-PER).** The first `vdt` and `avi` periods start at `reporting_start`; each later period starts at the `period_to` of the latest recorded report of its kind and ends at the generation instant.

**Pinned schemas, validated at generation.** The four FedRAMP files (the three document schemas and the common definitions they reference) are vendored byte for byte in `data/fedramp/`, their digests pinned by a test. Each document is validated against its schema (JSON Schema 2020-12, `$ref` resolved from the vendored copies by `$id`, never over the network) before anything is held. `format` is checked for `date-time` and `uri` by checkers this plugin registers from the standard library: jsonschema's own `date-time` check depends on an optional package and passes everything without it. An invalid document fails the profile (`req-fedramp-20x-vdr-generator`) with every error's JSON pointer. A new FedRAMP schema release is a data change: new vendored files and a new `schema_id`. No new dependency: `jsonschema` and `referencing` are already in core.

**FedRAMP ID (CDS-CSO-FID).** The 2026-06-24 schemas have no field for it. The ID is in each file's name, on the report node and in the fetch responses (`req-fedramp-20x-vdr-fetch`); the body stays exactly the schema's shape, and the Certification Package Overview it points to carries the ID.

**Kept (CDS-CSO-HAD).** The file store keeps every file and deletes nothing (`req-tap-files-immutable`), and this plugin never deletes a report node. A retention policy waits on `req-tap-files-retention` in core.

**Core dependency.** `FILE_CONTENTS` is `In Development` in core; the plugin's `requires_tap` rises to the first release that ships it. The generator's actor needs `files.create`; if the collector actor does not hold it, granting it is a core change.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-fedramp-20x-vdr-report-1 | One Node, One File | Proposed | Each run writes, per active profile, three `vdr_report` nodes and three held files, each file joined to its node by `FILE_CONTENTS` whose `sha256` equals the file's. | |
| req-fedramp-20x-vdr-report-2 | Validated Before Held | Proposed | A document that fails its schema is not held, no node is written for the profile in that run, and the error names the schema `$id` and the JSON pointer. | |
| req-fedramp-20x-vdr-report-3 | Formats Are Checked | Proposed | A document whose `detectedAt` is not an RFC 3339 date-time, or whose `certificationPackageOverviewUri` is not a URI, fails validation. | Proves the checkers are active. |
| req-fedramp-20x-vdr-report-4 | Periods Chain | Proposed | The first `vdt` and `avi` reports start at `reporting_start`; each later one starts at its predecessor's `period_to`; a check reports any gap, overlap or two reports following one. | |
| req-fedramp-20x-vdr-report-5 | Schemas Pinned | Proposed | The vendored schema files match their pinned digests, and every report records the `$id` and `$schemaVersion` it was validated against. | |
| req-fedramp-20x-vdr-report-6 | Kept | Proposed | No code path in the plugin deletes a `vdr_report` or its file. | |
| req-fedramp-20x-vdr-report-7 | FedRAMP ID Carried | Proposed | Every held file's name and every report node carry the profile's `fedramp_id`. | |

### Document Field Mapping
----
RID: `req-fedramp-20x-vdr-mapping`

Status: `Proposed`

How each schema field is filled from facts on the grid. It absorbs the former Backlog row "Accepted Vulnerability Record" (VER-RPT-AVI). The rule throughout: a field is written only from an observed value; an optional field with no value is omitted; nothing is invented. FedRAMP's own guidance points the same way: leave inapplicable ratings unset where the schema permits rather than inventing one, and schema validity alone does not make a report complete (vdr-migration FAQ 34 and 38, read 2026-11-24).

Rejected: reporting unknown LEV, IRV or PAIN as the worst case (the worst case is how deadlines are computed, not a statement that someone evaluated the vulnerability); omitting findings with missing facts (hides a vulnerability).

#### Implementation

**Findings covered.** Every `compliance_finding` with a non-empty `source` and `source_key` that a `vdr_evaluation` of the profile's `evaluation_scheme` evaluates.

**Disposition**, first match wins. An exception is in force when its `status` is `active` and its `expires_at` is null or after the generation instant; it covers a finding through `GRANTS_COMPLIANCE_EXCEPTION_INSTANCE` and `COVERS_COMPLIANCE_FINDING`.

| # | Disposition | When |
| --- | --- | --- |
| 1 | `false-positive` | An exception in force of kind `false-positive`, or `not-affected` with any justification but `inline_mitigations_already_exist`. |
| 2 | `remediated` | The finding's `status` is `resolved` (FedRAMP: no longer detected). |
| 3 | `accepted` | An exception in force of kind `accepted-risk` or `operational-requirement`; or the finding is open, not fully mitigated, and the anchor plus the `VER-TFR-MAV` row's hours (192 days) is not after the generation instant. |
| 4 | `fully-mitigated` | An exception in force of kind `not-affected` with `inline_mitigations_already_exist`, or `mitigated` with a current rating of N0. |
| 5 | `partially-mitigated` | Any other exception in force of kind `mitigated`. compliance_core does not say whether a mitigation is full, so the smaller claim is made. |
| 6 | `active` | Otherwise. |

The **anchor** is `evaluationCompletedAt`, else `detectedAt`: the earlier bound, as in `req-fedramp-20x-vdr-deadlines`.

**Which document.** `accepted` goes to Accepted Vulnerability Info and to the historical document's `acceptedVulnerabilities`; every other disposition goes to the Vulnerability Detail Report and to `activeVulnerabilities`. An accepted vulnerability whose exception lapses returns to the detail report (vdr-migration FAQ 37). A detail or accepted report lists every finding currently `active`, `accepted` or mitigated, and every finding whose state became `false-positive` or `remediated` inside the period (`req-fedramp-20x-vdr-finding-state`). The historical document lists every finding that has a state under the profile, at its latest state.

**`vulnerabilityDetail`.**

| Field | Source |
| --- | --- |
| `providerTrackingId` | `vdr-` and the first 24 hexadecimal characters of SHA-256 over `source`, U+001F and `source_key`. Derived from the finding's natural key, so stable across runs, reloads and grids, and opaque: no path, host or repository name leaves in it. |
| `detection.detectedAt` | `first_detected_at`; when null, the finding entity's creation time, and the supplementary text says the source gave no detection time. |
| `detection.detectionSource` | The `name` of the `compliance_scanner` that `DETECTS_COMPLIANCE_FINDING` it, or that `PERFORMS_COMPLIANCE_SCAN_RUN` the run that `REPORTS_COMPLIANCE_FINDING` it; else the finding's `source`. |
| `vulnerabilityDescription` | For each linked `compliance_vulnerability`, its `vuln_id` and `title`; for a finding with none, the finding's `name`. |
| `potentialAgencyImpact` | When rated, the rating and the name of the Search that produced it; omitted when unrated. |
| `evaluationCompletedAt` | The method row's `evaluated_at`; else the `observed_at` of the first state with `pain`, `likely_exploitable` and `internet_reachable` all set; omitted when no state ever was. |
| `isInternetReachable`, `isLikelyExploitable` | The method row; else `backed_factors` for the profile's `evaluation_scheme`; omitted when both are unknown. |
| `currentRating` | The method's `pain` as an integer; omitted when `null` or `false-positive`. |
| `painReductionEvents` | Each state whose `pain` is lower than the previous non-null `pain`: `reducedAt` its `observed_at`, `rating` its `pain`. `[]` when the finding was rated and never reduced; omitted when it was never rated. |
| `projectedNextReduction` | Omitted: nothing records a planned mitigation (`req-fedramp-20x-vdr-next-reduction`, Backlog). |
| `overdueStatus` | Below; omitted for `false-positive` and `remediated`. |
| `supplementaryRiskInformation` | Composed from the allowlist below: CVE ids and aliases; CISA KEV listing date and due date when `kev` is true; EPSS score and date; and each absence that applies (not rated, LEV or IRV not evaluated, detection time not given, class assumed, no method configured). The schemas have no KEV or CVE field, so they are carried here. |
| `finalDisposition` | `False Positive`, `Remediated`, `Fully Mitigated` or `Partially Mitigated` from the disposition; omitted for `active` and `accepted`. |

**`acceptedVulnerabilityInfo`.** `vulnerabilityDetail` as above. `acceptanceRationale` is the exception's kind and `description` (by compliance_core's convention, the business rationale); an empty description gives "`<kind>` exception recorded with no rationale" and a warning naming the exception. Acceptance by the 192-day rule gives "Not fully mitigated or remediated within 192 days of `<evaluation | detection>` (VER-TFR-MAV)".

**`overdueStatus`**, first match:

1. `kev` true and `kev_due_date` before the generation instant: overdue, "Past the CISA KEV due date `<date>` (VDR-TFR-KEV)".
2. Rating not complete and `detectedAt` plus the class's `VER-TFR-EVU` hours before the instant: overdue, "Not evaluated within `<n>` days of detection (VER-TFR-EVU, class `<x>`)".
3. The anchor plus `deadline_hours(class, pain, column(lev, irv))`, with unknown values read as N5 and true (`req-fedramp-20x-vdr-effective`), before the instant: overdue, naming the hours, the cell and the anchor, and which inputs were read as the worst case.
4. Otherwise not overdue, with "Due `<date>`", or "No FedRAMP timeframe for `<N>`" when `deadline_hours` returns `None`.

This is the exact deadline for a rated finding, computed in Python from `deadline_hours`. The shipped `vdr-deadlines` Search keeps its worst-case bound, and `req-fedramp-20x-vdr-partial` (Backlog) still concerns that Search.

**Nothing exploit-enabling (VER-RPT-NID).** Every text field is composed only from the sources named above. Never written: a finding's `description` or `summary`, `source_key`, any component, host, container, program, path, URL or port, a CVSS vector, or any free text a method returns (bases, rationales). Two provider-authored texts remain the provider's responsibility and the pages say so: the `name` of a finding with no vulnerability, and an exception's `description`.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-fedramp-20x-vdr-mapping-1 | Tracking Id Stable | Proposed | One `source` and `source_key` give the same `providerTrackingId` on every run and every grid; two different keys give different ids. | |
| req-fedramp-20x-vdr-mapping-2 | Required Fields Always Filled | Proposed | Every record has `providerTrackingId`, `detectedAt`, `detectionSource` and `vulnerabilityDescription`, including a finding with no `first_detected_at` and no vulnerability. | |
| req-fedramp-20x-vdr-mapping-3 | Unknown Is Omitted | Proposed | A finding the method did not rate has no `currentRating`; with LEV unknown to both the method and the evidence, no `isLikelyExploitable`; the supplementary text names each absence. | |
| req-fedramp-20x-vdr-mapping-4 | Disposition Precedence | Proposed | A table test covers each row of the disposition table and each pair of overlapping conditions. | |
| req-fedramp-20x-vdr-mapping-5 | Accepted Two Ways | Proposed | An `accepted-risk` exception in force puts the finding in Accepted Vulnerability Info with the exception's description as rationale; an open finding 192 days past its anchor goes there with the VER-TFR-MAV rationale; an expired exception returns the finding to the detail report. | Absorbs the former Backlog row Accepted Vulnerability Record (VER-RPT-AVI). |
| req-fedramp-20x-vdr-mapping-6 | False Positives Reported, Not Rated | Proposed | A false positive appears in the detail report with `finalDisposition` `False Positive` and no `currentRating` or `overdueStatus`. | |
| req-fedramp-20x-vdr-mapping-7 | Overdue Explained | Proposed | Each of the three overdue causes yields `isOverdue` true with its explanation, and the schema's rule that an overdue record has an explanation holds. | |
| req-fedramp-20x-vdr-mapping-8 | Reductions From History | Proposed | States N5, N3, N3, N2 give two reduction events; a finding never rated has no `painReductionEvents`; one rated and never reduced has `[]`. | |
| req-fedramp-20x-vdr-mapping-9 | Nothing Exploit-Enabling | Proposed | A finding whose description, `source_key` and component name each contain a marker string yields three documents in which no marker appears. | |

### Report Generator
----
RID: `req-fedramp-20x-vdr-generator`

Status: `Proposed`

A Schedule can fire only a collector (`req-tap-cares-scheduler-scope-1`), and emitters are Proposed and unbuilt (`req-tap-cares-v0-emitter`). Generation writes to the grid (states, report nodes, held files), which is what a collector does, so the generator is a derived collector like `vdr_max`. The on-demand path is the same collector run from the Administrivia panel (`run_collection`, which records `manual_run`). Neither needs a core change.

Rejected: a management command (no Schedule can fire it and it leaves no run record on the grid); waiting for emitters (the generator sends nothing anywhere; delivery is the consuming plugin's).

#### Implementation

`tap_plugin/fedramp_20x_vdr/collectors/vdr_report/collector.py`, registered as `vdr_report` under scope `fedramp_20x_vdr`. For each active profile, in `profile_key` order, independently:

1. Read the findings, exceptions, vulnerabilities, evaluations and states through Gryphon (`tap_grid.gryphon.read_scope`) and `backed_factors`.
2. Run the profile's method Search through `tap_grid.search.execute_search` with `method_inputs`, every page; validate and reduce the rows (`req-fedramp-20x-vdr-rating`).
3. Classify, and build the three documents in memory, with history from the stored states plus this run's.
4. Validate all three (`req-fedramp-20x-vdr-report`).
5. Submit the new states as one GRIFT batch.
6. Hold the three files.
7. Submit the three report nodes, their edges and `FILE_CONTENTS` as one GRIFT batch.

A failure fails that profile and writes nothing further for it; the other profiles proceed, and the run is failed and names each failed profile. A failure after step 6 leaves held files with no report node, a state core accepts (`req-tap-files-hold`), and does not advance the period chain, so the next run's period starts at the last recorded report and no gap appears.

No credential and no external call. The Schedule is the instance's, as for the coverage snapshot: weekly is often enough for every class (VER-TFR-MRH asks for at most 7 days at class D; VER-TFR-MHR asks for monthly).

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-fedramp-20x-vdr-generator-1 | Registered | Proposed | `vdr_report` is registered under scope `fedramp_20x_vdr` at `ready()` with a name and description, and reconciles to one `Collector` node. | |
| req-fedramp-20x-vdr-generator-2 | Three Per Profile | Proposed | One run on a grid with two active profiles and one inactive writes three reports for each active profile and none for the inactive one. | |
| req-fedramp-20x-vdr-generator-3 | Failures Stay Local | Proposed | With profile A's method returning an invalid row, A writes nothing, B writes its three reports, and the run is failed naming A. | |
| req-fedramp-20x-vdr-generator-4 | No Gap After A Failure | Proposed | A run that fails after holding files is followed by a run whose `vdt` period starts at the last recorded report's `period_to`. | |
| req-fedramp-20x-vdr-generator-5 | Reads Through Search | Proposed | Method rows are read only through `execute_search`, grid facts only through `read_scope`; the collector reads no `Entity` or `Edge` directly. | |
| req-fedramp-20x-vdr-generator-6 | On Demand Is The Same Run | Proposed | A run started from the Administrivia panel writes the same kinds of output as a scheduled run, and its run record has `manual_run` true. | |

### Programmatic Fetch
----
RID: `req-fedramp-20x-vdr-fetch`

Status: `Proposed`

Collectors and emitters (the first is the planned `regscale` plugin) and an agency's tooling need each document. This is the payload source for an emitter: core is building the emitter primitive (Issue# 1357 - tap), and delivery (destination, credentials, retries, the delivery record) is the emitter's. Nothing here sends anything. One Python function and one plugin API router give the documents out, and both serve the stored document, never a fresh one:

- the page, the download and the API then return the same bytes, so human-readable and machine-readable output agree by construction (CDS-CSO-CBF);
- a snapshot is what was reported (CDS-CSO-HAD);
- a document is one period of a chain (VER-RPT-PER), and because methods compute on read, regenerating would either mint a new period or give an old period a different answer;
- the digest is a stable `ETag`, so a consumer uploads each document once.

A consumer that needs a fresher document runs the generator.

#### Implementation

**Python**, in `tap_plugin/fedramp_20x_vdr/reports.py`, typed and importable. These are the names an emitter's payload builder calls, and they are the contract: a change to them is a breaking change of this plugin.

- `list_reports(profile_key, *, kind=None, db_alias)` returns `ReportRef` values, newest first: `report_id`, `file_id`, `kind`, `period_from`, `period_to`, `generated_at`, `schema_id`, `schema_version`, `fedramp_id`, `sha256`, `file_name`.
- `fetch_document(profile_key, kind, *, generated_at=None, db_alias)` returns a `ReportDocument` (its `ReportRef` and `content` bytes); the latest when `generated_at` is `None`; raises `ReportNotFound` when there is none.

Nodes are read through `read_scope`, bytes through core's gateway `open_file`, so the `files.read` check, the digest check and the operation log are core's.

**HTTP**, a router returned by `get_api_router()`, mounted by core at `/api/v1/plugins/fedramp_20x_vdr/`:

| Route | Returns |
| --- | --- |
| `GET reports/{profile_key}` | The `ReportRef` list as JSON, newest first; optional `?kind=`. |
| `GET reports/{profile_key}/{kind}/latest` | The latest document of that kind. |
| `GET reports/{profile_key}/{kind}/{generated_at}` | The document generated at that instant (`YYYYMMDDTHHMMSSZ`). |

A document response is the stored bytes verbatim, `Content-Type: application/json`, `ETag` the digest, `Link: <schema $id>; rel="describedby"`, and `Content-Disposition: inline` with the held file's name, which carries the FedRAMP ID. `kind` is `vdt`, `avi` or `mrh`; anything else, an unknown profile, or no document is `404`; a caller without `files.read` is `403`; an integrity failure is `500` with no detail.

**Auth.** Core's API has session authentication only (`tap_api/auth.py`). In-process callers such as a consuming plugin use the Python functions and need no HTTP authentication. Retrieval by a party outside the instance, which VER-TFR-MRH describes ("for automated retrieval ... using an API service"), needs token or service authentication in core: a core change, `req-fedramp-20x-vdr-api-token` (Backlog).

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-fedramp-20x-vdr-fetch-1 | Latest By Default | Proposed | `fetch_document` without `generated_at`, and the `latest` route, return the newest document of the kind. | |
| req-fedramp-20x-vdr-fetch-2 | Same Bytes Everywhere | Proposed | The API body, the Python `content` and the core download of the same file are identical, and their digest equals the node's. | |
| req-fedramp-20x-vdr-fetch-3 | Never Generates | Proposed | A fetch writes no node and runs no Search; with no document the route is `404` and the function raises `ReportNotFound`. | |
| req-fedramp-20x-vdr-fetch-4 | Headers Stated | Proposed | A document response carries the content type, the `ETag`, the `Link` to the schema `$id` and a file name containing the FedRAMP ID. | |
| req-fedramp-20x-vdr-fetch-5 | Gated By The Store | Proposed | A logged-in user without `files.read` is refused by the route and by the function. | |

### Download Links
----
RID: `req-fedramp-20x-vdr-download`

Status: `Proposed`

A person downloads each document as JSON. Core already has both halves: `GET /files/<identifier>/download` serves a held file as an attachment with its recorded media type to a user holding `files.read` (`req-tap-files-download`), and the table panel builds a same-origin link per row from a Search (`row_url_template`, `req-web-stdpanel-table-rows-5`). So the reusable capability is one Search and one panel configuration, placed on any page with a different `kind`. No new panel type, route or core change.

Rejected: three one-off buttons; a plugin download route (a second route for bytes core already serves).

#### Implementation

A Search `vdr-reports`, shipped as a GRIFT node in `grift/searches.grift.json`: inputs `profile_key` and `kind`, both optional; rows `report_id`, `file_id` (the `tap_file` joined by `FILE_CONTENTS`), `file_name`, `kind`, `period_from`, `period_to`, `generated_at`, `record_count`, `schema_version`, newest first. Gryphon is the first choice; if it cannot express the join or the order, the choice between a Gryphon capability and a `module` runner goes to the maintainer (AGENTS.md).

The panel configuration is a table panel bound to `vdr-reports` with `kind` fixed, `row_url_template` `/files/{file_id}/download`, and `file_name` as the visible column, so each row is a download link and the first row is the latest. A button-styled control with a fixed label is a `tap_web` enhancement, not needed here.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-fedramp-20x-vdr-download-1 | Rows Carry The File | Proposed | Each `vdr-reports` row's `file_id` is the `tap_file` that `FILE_CONTENTS` joins to that report. | |
| req-fedramp-20x-vdr-download-2 | The Stored Document | Proposed | Following a row's link downloads bytes identical to the fetch of the same report. | |
| req-fedramp-20x-vdr-download-3 | Reusable By Configuration | Proposed | The same configuration with each of the three `kind` values renders download links for that kind only, with no code. | |
| req-fedramp-20x-vdr-download-4 | No New Route | Proposed | The plugin declares no URL that serves file bytes. | |

### Document Markup Search
----
RID: `req-fedramp-20x-vdr-document-markup`

Status: `Proposed`

Each report page has two parts: a heading that says what the viewer is looking at, and the document itself, formatted. Both are shown with core's HTML panel (slug `html`, `tap_web/specs/spec-web-panels-html.md`), which renders cleaned markup from a bound Search's row field with a closed vocabulary and the theme's palette. This Search is what emits that markup, from the stored document, so the page shows the bytes the API and the download serve.

**What the HTML panel can and cannot do today (read 2026-11-24).** The heading fits it exactly: headings, paragraphs, lists and links to `https` hosts the panel may narrow to. The body fits it **without colour**: the `code` feature admits `pre` and `code`, so formatted JSON shows as monospaced text. Syntax colouring does not fit, for two reasons. First, `class` is limited to ten named classes, none of them a token class, and a class outside them is removed (`req-web-panels-html-clean-7`). Second, colouring by `span` per token would pass the 2000-element ceiling (`req-web-panels-html-clean-8`) on any document past a few hundred tokens. A document over the 262144-byte ceiling fails closed even uncoloured. The cleaner is not loosened for this. The gap goes to core as `req-fedramp-20x-vdr-syntax-colour` (Backlog, core change) with two candidates. One is a narrow extension of the HTML panel's vocabulary: a set of palette-token token classes allowed only on `span` inside `pre`, which also needs the element ceiling raised for that feature. The other is a new `tap_web` panel type for JSON that parses a JSON value and generates escaped, coloured markup itself, so no markup is cleaned and the cleaner is untouched. This spec recommends the second, because it needs no change to what the cleaner admits or to its limits. Until then the body is formatted and uncoloured.

#### Implementation

A `module` Search runner `vdr-report-markup` (`tap_plugin/fedramp_20x_vdr/searches/markup.py`), shipped with a Search node in `grift/searches.grift.json`. It is a runner and not a Gryphon Search because it reads a held file's bytes, which Gryphon does not do (the reason recorded in the Search's description, AGENTS.md). Inputs: `profile_key` (required unless exactly one profile is active), `kind` (`vdt`, `avi` or `mrh`), and optional `generated_at` (default the latest). It reads through `fetch_document` (`req-fedramp-20x-vdr-fetch`), runs nothing else and writes nothing. It returns one row:

| field | markup |
| --- | --- |
| `heading_html` | An `h2` naming the document; a paragraph saying which FedRAMP rules it answers (`vdt`: VER-RPT-VDT and VER-RPT-PER; `avi`: VER-RPT-AVI; `mrh`: VER-TFR-MRH); the period, `generated_at`, FedRAMP ID, class and whether it was assumed, and the schema `$id` and `$schemaVersion`; a list of links: the FedRAMP rule pages under `https://www.fedramp.gov/2026/reference/vulnerability-evaluation-and-reporting/`, the schema `$id` URL, and this specification in the plugin's repository. |
| `body_html` | `pre` and `code` holding the document, parsed and re-serialised with two-space indentation and every character escaped. A document whose formatted form passes the HTML panel's byte ceiling is not cut: the body says how large it is and points at the download, because a partial document shown as the document would mislead. |
| `report_id`, `file_id` | For a panel that links to the report or the file. |

The rule-page anchors are taken from the rule names (`#vulnerability-details`, `#accepted-vulnerability-info`, `#historical-activity`, `#persistent-reporting`) and checked against the live page when built.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-fedramp-20x-vdr-document-markup-1 | Cleans Unchanged | Proposed | For each kind, `heading_html` cleaned by the HTML panel's cleaner with features `text`, `headings`, `lists` and `links`, and `body_html` cleaned with `text` and `code`, are each unchanged by cleaning. | The markup is made to fit the vocabulary; nothing is relied on to be stripped. |
| req-fedramp-20x-vdr-document-markup-2 | The Stored Document | Proposed | The JSON value parsed back out of `body_html` equals the value of the bytes `fetch_document` returns for the same report. | |
| req-fedramp-20x-vdr-document-markup-3 | Escaped | Proposed | A vulnerability title containing markup appears in `body_html` as escaped text. | |
| req-fedramp-20x-vdr-document-markup-4 | Too Large Is Stated | Proposed | A document whose formatted form passes the ceiling yields a body that states its size and points at the download, and contains none of the document. | |
| req-fedramp-20x-vdr-document-markup-5 | Absence Stated | Proposed | With no report of the kind for the profile, both fields say so and name the profile. | |
| req-fedramp-20x-vdr-document-markup-6 | Read Only | Proposed | The runner writes nothing and runs no other Search. | |

### Vulnerability Detail Report Page
----
RID: `req-fedramp-20x-vdr-page-vdt`

Status: `Proposed`

The page that shows the latest Vulnerability Detail Report of a profile (VER-RPT-VDT, VER-RPT-PER), explains it, and lets a person download it.

#### Implementation

Page slug `vdr-report-detail`, seeded by `grift/pages.grift.json`. Page input `profile_key`. Panels, top to bottom, all configuration:

1. **Heading.** An `html` panel bound to `vdr-report-markup` with `kind` `vdt`, `field` `heading_html`, `features` `text`, `headings`, `lists`, `links`, `link_schemes` `https`, and `link_hosts` limited to `www.fedramp.gov`, `fedramp.gov` and `github.com`. It also states that free text in the report is limited by VER-RPT-NID (`req-fedramp-20x-vdr-mapping`).
2. **Document.** An `html` panel bound to the same Search, `field` `body_html`, `features` `text` and `code`, `max_bytes` 262144. Formatted, and coloured once `req-fedramp-20x-vdr-syntax-colour` lands.
3. **Download.** The download table of `req-fedramp-20x-vdr-download` with `kind` `vdt`.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-fedramp-20x-vdr-page-vdt-1 | Heading Explains | Proposed | The heading names the document, VER-RPT-VDT and VER-RPT-PER, the period and the FedRAMP ID, and links to the rule page, the schema and this specification. | |
| req-fedramp-20x-vdr-page-vdt-2 | Same Document | Proposed | The document shown and the file downloaded from the page parse to the same JSON value. | |
| req-fedramp-20x-vdr-page-vdt-3 | Configuration Only | Proposed | The page adds no panel type and no code; it is a Page node and three panel configurations. | |

### Accepted Vulnerability Info Page
----
RID: `req-fedramp-20x-vdr-page-avi`

Status: `Proposed`

The page that shows the latest Accepted Vulnerability Info of a profile (VER-RPT-AVI), explains it, and lets a person download it.

#### Implementation

Page slug `vdr-report-accepted`, seeded by `grift/pages.grift.json`. Page input `profile_key`. The three panels of `req-fedramp-20x-vdr-page-vdt` with `kind` `avi`. The heading also states that acceptance rationales are the provider's own words, taken from its exceptions.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-fedramp-20x-vdr-page-avi-1 | Heading Explains | Proposed | The heading names the document, VER-RPT-AVI, the period and the FedRAMP ID, and links to the rule page, the schema and this specification. | |
| req-fedramp-20x-vdr-page-avi-2 | Same Document | Proposed | The document shown and the file downloaded from the page parse to the same JSON value. | |
| req-fedramp-20x-vdr-page-avi-3 | Configuration Only | Proposed | The page adds no panel type and no code. | |

### Historical Activity Page
----
RID: `req-fedramp-20x-vdr-page-mrh`

Status: `Proposed`

The page that shows the latest Historical VER Activity document of a profile (VER-TFR-MRH), explains it, lets a person download it, and gives the address a program fetches it from: the "URL and access instructions" artifact VER-TFR-MRH names.

#### Implementation

Page slug `vdr-report-history`, seeded by `grift/pages.grift.json`. Page input `profile_key`. The three panels of `req-fedramp-20x-vdr-page-vdt` with `kind` `mrh`. The heading also gives the route `GET /api/v1/plugins/fedramp_20x_vdr/reports/<profile_key>/mrh/latest` and the authentication it needs (`req-fedramp-20x-vdr-fetch`), and states that reduction times are when the generator first observed the lower rating (`req-fedramp-20x-vdr-finding-state`).

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-fedramp-20x-vdr-page-mrh-1 | Heading Explains | Proposed | The heading names the document, VER-TFR-MRH, the span and the FedRAMP ID, and links to the rule page, the schema and this specification. | |
| req-fedramp-20x-vdr-page-mrh-2 | Same Document | Proposed | The document shown and the file downloaded from the page parse to the same JSON value. | |
| req-fedramp-20x-vdr-page-mrh-3 | Access Stated | Proposed | The heading names the fetch route and the authentication it needs. | |

### v0 Non-Goals
----
RID: `req-fedramp-20x-vdr-nongoals`

Status: `Proposed`

The plugin does not, in v0:

- ship pages, panel types or a layout beyond the three report pages, which are configuration of core panels; the Searches are the surface other pages read;
- mint findings, vulnerabilities, scanners or scan runs, or store a detection time (compliance_core owns them; Issue# 43 - compliance-core-tap);
- store a deadline: the deadline Searches compute dates on read in the runner, and no node holds one (the report and finding-state nodes hold the instants they were generated and observed, never a deadline);
- evaluate a finding that has no vulnerability edge, or a resolved one;
- compute the exact deadline for an evaluation with any factor set; v0 shows the worst-case bound (`req-fedramp-20x-vdr-partial`);
- store PAIN as an evaluation, an owner, an effective profile or a roll-up: the reach computes on read (`req-fedramp-20x-vdr-reach`) and a method plugin computes the level; the one PAIN the plugin writes is the record of what a method returned and when (`req-fedramp-20x-vdr-finding-state`);
- score a finding: the formula, weights and thresholds belong to a method plugin such as `stackarmor_vdr`;
- invent a timeframe for PAIN N0 or N1 (`req-fedramp-20x-vdr-low-pain`);
- represent the system's class as anything but the default input (`req-fedramp-20x-vdr-class`);
- schedule or seed the coverage snapshot's Search or Schedule (the playground owns both; `req-fedramp-20x-vdr-coverage-snapshot`);
- group findings, evaluate false positives, check detection cadence, or treat failures as vulnerabilities (the Backlog rows above);
- deliver a report document anywhere: transport to a trust center belongs to the consuming plugin (the first planned is `regscale`), and the emitter primitive to core's tap_cares (`req-tap-cares-v0-emitter`, Issue# 1357 - tap); this plugin only produces, validates, keeps and serves the documents (`req-fedramp-20x-vdr-fetch`);
- sign documents, publish a public tier that withholds open reachable and exploitable findings, or emit VEX: the publication concerns of a method such as Aydlette's (its REQ-PUB-1, -3 and -4) belong to a publication pipeline, not to this export;
- seed a Schedule or a report profile: both are the instance's (`req-fedramp-20x-vdr-generator`, `req-fedramp-20x-vdr-profile`).

## Model catalog

Design-time; superseded by the manifest once the owning requirement is `Implemented`.

| Model | Entity type | Category | Rationale |
| --- | --- | --- | --- |
| `vdr_evaluation` | `fedramp_20x_vdr__vdr_evaluation` | Judgement | A judgement by a party at a time, one per finding per scheme, kept apart from the scanner's observation. |
| `vdr_timeframe` | `fedramp_20x_vdr__vdr_timeframe` | Reference data | One cell of a FedRAMP table, so the table is data with a cited source. |
| `vdr_report_profile` | `fedramp_20x_vdr__vdr_report_profile` | Declaration | What a provider declares about how one offering reports (FedRAMP ID, package URI, class, start, scheme, method); a node because TAP has no plugin configuration and the facts deserve history. |
| `vdr_finding_state` | `fedramp_20x_vdr__vdr_finding_state` | Observation | A change point in one finding's reported rating or disposition under one profile; the history methods do not keep. |
| `vdr_report` | `fedramp_20x_vdr__vdr_report` | Format record | What one held report file is: kind, period, profile, schema; joined to the file by core's `FILE_CONTENTS`. |

## Edge types

| Edge | From → To | Properties | Rationale |
| --- | --- | --- | --- |
| `EVALUATES_COMPLIANCE_FINDING` | `vdr_evaluation` → `compliance_finding` | none | Which finding an evaluation judges. |
| `CITES_FACTOR_EVIDENCE` | `vdr_evaluation` → `compliance_evidence` | `factor`, `basis`, `note` | The proof that lowers one factor; the existing finding-to-evidence edge cannot start at an evaluation. |
| `RUNS_SEARCH` | `vdr_report_profile` → `search` | none | Which Search rates the profile's findings; an edge rather than an id column, so the method is visible on the graph and no hidden id map exists. |
| `TRACKS_COMPLIANCE_FINDING` | `vdr_finding_state` → `compliance_finding` | none | Which finding a state describes. |
| `APPLIES_REPORT_PROFILE` | `vdr_report` → `vdr_report_profile` | none | Which profile a report was generated under. |
| `FOLLOWS_VDR_REPORT` | `vdr_report` → `vdr_report` | none | The previous report of the same profile and kind, so the period chain of VER-RPT-PER is on the graph and a gap or fork is a check. |
| `FILE_CONTENTS` (core, `tap_files`) | `tap_file` → `vdr_report` | `sha256` | Declared by core, written by this plugin: the report node is the held file's format record. |

## Reference data

| Document | Contents | Seeded by |
| --- | --- | --- |
| `grift/timeframes.grift.json` | The 53 `vdr_timeframe` rows. | `import_plugin_grift` |
| `data/evidence_basis.json` | The closed list of evidence bases, with a schema. | Loaded by the plugin |
| `data/method_rows.schema.json` | The method rating contract (`req-fedramp-20x-vdr-rating`). | Loaded by the plugin |
| `data/fedramp/*.json` | The three FedRAMP 2026-06-24 report schemas and their common definitions, vendored byte for byte with pinned digests. The licence of FedRAMP's schema files is confirmed before vendoring. | Loaded by the plugin |
| `grift/searches.grift.json` | The `vdr-reports` and `vdr-report-markup` Search nodes. | `import_plugin_grift` |
| `grift/pages.grift.json` | The three report pages and their panel configurations. | `import_plugin_grift` |
