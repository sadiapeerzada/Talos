# PR-00: Research execution backlog and issue index

Date: **2026-11-15**. Authority: supplied full research roadmap; scope here is an issue index and acceptance criteria. **No later PR is implemented or authorized for execution by this document.** Base `ac8c613295ddc4fc1bb6989707ebe86a0074c0e4`. See [audit](research_gap_audit.md), [claims](research_claim_registry.md) and [decision gate](research_go_no_go.md).

Status vocabulary: **VERIFIED** = observed implementation/evidence; **INFERRED** = recommended response to a supported gap; **PENDING** = unfinished work; **BLOCKED** = named human/input dependency. The IDs below are local issue identifiers, not invented GitHub issue numbers. The user requested a PR, not creation of a separate set of remote issues.

## Prioritized issue index

| ID | Priority / status | Evidence / affected claims | Next scope and acceptance | Owner / dependency |
|---|---|---|---|---|
| BG-01 | P0 / PENDING | A01, C19: score mismatch | PR-01: preserve legacy meaning/name and define versioned candidate score with explicit opportunity denominator; approve semantics before empirical calibration. Trace equation to implementation. | Researcher decides metric; implementation after PR-00 review |
| BG-02 | P0 / PENDING | A02–03, C18–20: fixture oracle/call semantics | PR-01: legacy isolation plus typed CONFIRMED/BLOCKED/ATTEMPTED/NO_VIOLATION/UNKNOWN; require trusted audit/state evidence for committed forbidden outcomes; no silent relabeling of history. | Engineer + researcher policy contract |
| BG-03 | P0 / PENDING | A07–08, C23: k>0, rounded rates, shared-ID intersection | PR-01/05: make event definition explicit; retain integer k/n and per-repeat events; detect missing/duplicate pairs; deterministic replay; later cluster-aware statistics with prespecified unit. | Engineer + statistical reviewer |
| BG-04 | P0 / BLOCKED | A04, C15: Figure 5 mismatches caption/data | Researcher selects original figure/data/license or authorizes a separate v2 replacement from real evidence; archive v1 intact. No model results inferred from image. | Researcher/asset author; PR-11 |
| BG-05 | P0 / BLOCKED | A05–06, C06–10: missing raw run linkage | Obtain original 70-attempt run, auto-fix transcript, matched 35-template LangChain results, timestamps and source hashes; record missing cells if unavailable. Distinguish 35 instances from 37 messages. | Researcher artifact custodian; PR-05/10/12 |
| BG-06 | P0 / BLOCKED | A15: manuscript identity/date | Select authoritative 20-page baseline and complete matching TeX/figures/bibliography/build; resolve Aug17 metadata versus roadmap Nov8; hash and archive separately before v2 edits. | Researcher; PR-11 |
| BG-07 | P0 / PENDING | A09, A17: unfamiliar tools/domains | PR-02: portable target profile/schema and graph roles, unknown classification/abstention, renamed-tool tests; portable scorer must not import sample_agents. | Engineer; depends on BG-02 |
| BG-08 | P0 / BLOCKED | C25, A17: external validity | PR-03: synthetic IT-helpdesk/document-sharing and benign tasks, independent custody evidence, state/reset contracts and isolated side effects. Authentic model study later needs allowlist/budget. | Researcher recruits target custodians; engineer implements after review |
| BG-09 | P1 / PENDING | C01–05, literature ledger | PR-04/08/11: version portable corpus and dated OWASP Agentic 2026/LLM 2026/MITRE mappings; verify literature capability cells, including AgentDojo, Agent vs. Agent, Promptfoo and PyRIT. Leave historical Talos-35 unchanged. | Engineer/researcher literature review |
| BG-10 | P0 / PENDING | A12, C27: learning/state confounds | PR-05: immutable run manifest, learning DB snapshot/disable switch, budgets, full request/turn counts, resets, seeds/order, failures, raw events, hashes and crash-safe resume; offline by default. | Engineer; depends on BG-02/07 |
| BG-11 | P0 / BLOCKED | A02, A17: independent labels absent | PR-06: blinded annotation export and ingestion, two real raters, adjudication, confusion matrix/kappa with uncertainty. Synthetic labels only for code tests; retain actual human provenance. | Researcher recruits raters, approves data; engineer prepares tooling |
| BG-12 | P0 / PENDING | C28: advantage untested | PR-07: graph-blind static, graph-aware static, generic mutation/equal-budget retry and feedback arms on identical targets/oracle; count target requests and attacker costs separately; no TEST tuning. | Engineer + protocol owner, after BG-02/07/10 |
| BG-13 | P1 / PENDING | C01–02, C25: external comparator absent | PR-08: pin one operationally commensurate Promptfoo/PyRIT release and common adapter/oracle/budget; AgentDojo as compatible benchmark if possible, otherwise qualitative comparison. | Researcher approves comparator protocol |
| BG-14 | P0 / BLOCKED | no frozen protocol/allowlist/budget | PR-09 only after signed researcher GO: DEV pilot, then immutable held-out real-model matrix, all failure/exclusion cells and cost/state evidence. No external financial/email effects. | Researcher execution authorization, credentials and resource caps |
| BG-15 | P0 / PENDING | A08, C23, C28 | PR-10: cluster-aware effect sizes, unique adjudicated root causes, discovery-budget curves, false positives, missing data, benign utility/cost/latency and risk sensitivity; report negative outcomes. | Statistician/researcher, requires actual frozen data |
| BG-16 | P1 / BLOCKED | C01–28 and manuscript source gaps | PR-11: archive supplied v1, align v2 text/equations/tables/figures 1:1 with evidence; remove unsupported claims; build chosen venue source, check affiliations/format. | Researcher confirms source/venue/authorship; depends on evidence |
| BG-17 | P1 / PENDING | A13, A15, licensing gaps | PR-12: clean-clone offline analysis reproduction, pins/SBOM/license/redaction manifest, meaningful non-saturated risk regression gate and release signoff. No claims from public visibility alone. | Engineer + human release owner |
| BG-18 | P2 / PENDING | two-hop notes demo only | Optional PR-13: automated controlled multi-agent setup/search with matched single-agent control, after core study. Demonstration does not establish general multi-agent search. | Researcher explicit scope approval |
| BG-19 | P1 / BLOCKED | T4: dirty tree's stricter policy fails clipping test | Researcher decides intended confirmation policy and whether to retain local adapter/report changes. Separate code change/test update after PR-00; do not erase or incorporate user work. | Original change owner |
| BG-20 | P1 / PENDING | T1 storage import, A16, CI matrix | Future infrastructure PR: configurable isolated storage before dashboard import; dependency compatibility/pins; CI 3.11/3.12 proof; explicitly offline tests, no key-triggered inference. Preserve full T1–T4 evidence. | Engineer; not a product fix in PR-00 |

## Recommended next PR, held for review

**INFERRED recommendation: PR-01 only, “Version legacy metrics and establish outcome semantics.”** Keep its scope to BG-01/02/03 with minimal interfaces required for later portability. Do not bundle new targets, new scans, manuscript rewrites or PR-02 into it.

Reviewable acceptance requirements:

1. Preserve historical files, hashes and reproduction path; explicitly version oracle and risk meanings, with researcher-approved policy/metric contract.
2. Give attempted, blocked, accepted-but-rolled-back, committed forbidden, legitimate authorized and unobservable outcomes distinct typed verdicts. Confirmed impact needs trusted committed state evidence with event references.
3. Add meaningful negative/error/unknown controls, including mismatched domains and missing/duplicate audit events; current simulated fixtures alone cannot serve as independent validation.
4. Retain exact integer outcomes and document the binary event definition; separate repeated attempts, message deliveries, tool executions and vulnerability groups. Detect invalid paired inputs instead of silently dropping them.
5. Show legacy offline tests still work without historical output mutation. New test-only fixtures are not empirical results or human labels.
6. Candidate v2 risk definition and any manuscript wording change require explicit design review; no CVSS-calibration claim without evidence.

**BLOCKED execution boundary:** wait for the user's PR-00 review before implementing this recommendation. No signed study protocol, independent labels or endpoint execution budget is inferred from approval to write audit documentation.

## Roadmap dependency/gate inventory

| Roadmap PR | Deliverable boundary | Gate before execution/completion |
|---|---|---|
| PR-00 | custody, claims, backlog, go/no-go; offline test evidence | documentation review; missing source/raw-run cells explicitly recorded |
| PR-01 | oracle and metric correction, legacy/v2 isolation | PR-00 review and policy/metric decisions; no empirical calibration claim |
| PR-02 | portable profile/graph classification | versioned semantics and renamed/disjoint tool tests |
| PR-03 | safe additional domains + benign tasks | custodianship and synthetic state contracts; later live work needs separate authority |
| PR-04 | portable corpus + standards crosswalk | legacy freeze, provenance and source-verified mapping |
| PR-05 | immutable recorder/protocol execution infrastructure | reset/cost/budget/learning-state controls and offline failure tests |
| PR-06 | independent oracle validation + held-out custody | actual raters/labels and approved data splits; automation cannot approve itself |
| PR-07 | equal-budget baselines and ablations | common target/oracle/budget and frozen test boundary |
| PR-08 | external comparator | pinned license/version and defensible comparability |
| PR-09 | approved pilot then held-out model study | signed researcher GO, allowlist, funding, endpoints, safety limits |
| PR-10 | analysis and adverse-result audit | complete immutable data; prespecified experimental unit/statistics |
| PR-11 | manuscript v2 | selected editable project, evidence alignment, venue/authorship decisions |
| PR-12 | artifact release | clean-clone reproduction, privacy/licensing review, human release approval |
| Optional PR-13 | automated multi-agent search | core evidence complete, separate approved exploratory protocol |

**VERIFIED TODO search:** `rg -n 'TODO|FIXME|XXX|NotImplemented|pass$' talos` found `NotImplementedError` in the abstract Brain interface (`sample_agents/brain.py:274`), not a standalone implementation defect. This issue index includes methodological/documentation gaps even when no TODO marker exists. **PENDING** items remain open; no reviewer, label, experiment or signed approval is fabricated to close them.
