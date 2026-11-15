# PR-00: Research go/no-go and human decisions

Date: **2026-11-15 (Asia/Kolkata)**. Audited base: `ac8c613295ddc4fc1bb6989707ebe86a0074c0e4`. PR branch: `research/pr-00-baseline-custody`. This records an automated audit recommendation; it is **not** a researcher signature, independent review, budget authorization or approval of PR-01.

Statuses: **VERIFIED** = inspected facts; **INFERRED** = recommendation; **PENDING** = incomplete evidence/review; **BLOCKED** = named missing human decision/input.

## Decision

**INFERRED: GO for human review of the PR-00 documentation. NO-GO for broader empirical claims, new experiments, live inference, external target scans, production side effects or starting PR-01 in this task.** Existing offline tests passed on committed main; that does not close measurement/provenance gaps. The original working tree has a separately documented test failure and remains untouched.

PR-00 outputs: [gap audit](research_gap_audit.md), [claim registry](research_claim_registry.md), [execution backlog](research_execution_backlog.md), and this decision record. Only these four documentation files are to be committed. Original README, reports, research JSON, implementation and tests are preserved. Branch/commit/file list and test results belong in the PR description; obtain exact SHA using `git rev-parse HEAD` on this branch.

## PR-00 acceptance accounting

| Requirement | Status | Evidence / limit |
|---|---|---|
| Snapshot committed main and original working tree separately | VERIFIED | base ac8c613; original bf8bb25 and 4 dirty/untracked file fingerprints; isolated worktree |
| Read roadmap/execution instructions and inspect repository/tests | VERIFIED | custody/input hashes, path inventory, implementation table and test transcript in audit |
| Offline tests with exact commands/results | VERIFIED | base: 83 pass / 1 warning; dirty tree: 79 pass / 1 fail / 1 warning; environment-only failed attempts retained |
| Workflow definition and available remote status | VERIFIED / PENDING | Python 3.11/3.12 workflow inspected; GitHub queries returned empty lists, not proof of success; historical job logs missing |
| Dependencies/environment provenance | VERIFIED / BLOCKED historical | local Python 3.13.7 resolved freeze; historical lock/run environment absent |
| Every numbered table/figure linked or explicitly unsupported | VERIFIED inventory / PENDING evidence | C01–C17 in registry, including Figure 5 mismatch and missing generation commands/artifact hashes |
| Original raw result/report hashes retained | VERIFIED | J1/R1–R7, all base tracked file fingerprints; no historical rewrite or recalculation in place |
| Complete selected manuscript source and nonpublic raw traces | BLOCKED | local TeX/PDF candidates exist, exact baseline/build/figures and original run logs unconfirmed |
| Human review and decision on next PR | PENDING | no signature or independent approval asserted |

PR-00 documents the absence of required evidence; it cannot manufacture missing artifacts to make the research gate pass. The roadmap's literal full historical table/figure reproducibility criterion therefore remains partially BLOCKED, even though the audit delivery is ready for review.

## Full empirical study gate

| Condition | Current status | What would close it |
|---|---|---|
| Oracle matches trusted authorization and committed state | BLOCKED | PR-01/02 contracts and independent validation; error/rollback/blocked/unknown controls |
| Code/paper risk-score semantics agree | VERIFIED mismatch; BLOCKED design | approve legacy naming and versioned metric; later align equation and calibration claims |
| Independent human labels, false positives and agreement | BLOCKED | two real raters, adjudication and custody; Codex output cannot be independent human truth |
| Genuine LLM-backed independently controlled targets | BLOCKED | signed controlled target matrix, ownership/authorship evidence and actual approved runs |
| Additional held-out domain(s) and benign utility | PENDING | domain/task manifests with family-level DEV/TEST separation and clean-task outcomes |
| Equal-budget graph-blind and retry controls | PENDING | common target/oracle, request accounting, frozen adaptive/no-feedback arms |
| Immutable complete event/state evidence and analysis | BLOCKED | original logs if available; future versioned recorder, hashes, source/dependency/model manifests |
| Literature/standards and novelty positioning | PENDING | full primary-source cell ledger; correct AgentDojo/modern scanner framing and versioned 2026 crosswalk |
| Authoritative paper and figure custody | BLOCKED | select matching source/PDF, resolve Figure 5 provenance/license and date discrepancy |
| Budget, allowlist, isolation and release permissions | BLOCKED | researcher signs exact endpoints, ownership, maximum requests/tokens/cost, duration, retention and release boundaries |

If these cannot be completed, **INFERRED** recommendation is a bounded prototype/systems paper, or defer the full empirical paper. A negative or mixed future study is acceptable. Current 35-template fixture outcomes do not establish production safety or generalization.

## Decisions requiring a human

| Decision ID | Status / responsible person | Concrete decision or artifact required |
|---|---|---|
| HD-01 | BLOCKED / manuscript owner | Select authoritative baseline PDF and matching complete editable source. Candidate PDF has Aug17 metadata whereas roadmap says Nov8; local TeX candidates differ. Supply/identify dependencies, figures and bibliography; no reconstruction from PDF. |
| HD-02 | BLOCKED / figure owner | Explain Figure 5's unrelated model heatmap, identify original data/source/license and decide its treatment in a separately approved v2 manuscript. Do not imply the displayed models were tested by Talos. |
| HD-03 | BLOCKED / experiment custodian | Provide original per-attempt tool/state traces, command/source/dependency manifests, one-repeat paired run, matched LangChain-35 reports and auto-fix transcript, or confirm they are unavailable so claims can be narrowed. |
| HD-04 | BLOCKED / policy and metric owner | Decide authorization contract, what constitutes committed unauthorized impact, uncertainty treatment, vulnerability unit, legacy risk identity and candidate v2 opportunity denominator. |
| HD-05 | BLOCKED / original change owner | Decide whether the dirty tree's stricter first-turn confirmation rule is intended and how its clipping test should change. Review local adapter/report modifications separately; PR-00 makes no such choice. |
| HD-06 | BLOCKED / principal researcher | Approve hypotheses, target matrix, splits, baselines, budgets, statistical units and protocol amendments before future pilot/frozen study. No tuning on held-out outcomes. |
| HD-07 | BLOCKED / principal researcher | Obtain independent target custody/authorship and recruit actual human raters. Identify who signs labels/adjudications and retains the blinded data. |
| HD-08 | BLOCKED / execution owner | Sign allowlist, researcher control of targets, isolated synthetic effects, model IDs/endpoints/accounts and exact request/token/cost caps before inference or security scans. No real refunds/emails. |
| HD-09 | PENDING / release owner | Confirm synthetic/publishable data, licenses for repo/dependencies/figures, secret/PII redaction and retention rules; approve what can be released. Public visibility is not a license. |
| HD-10 | PENDING / authors | Select venue, authorship/affiliation, disclosure, anonymization and submission policy after evidence is ready. IEEE placeholder header is not evidence of publication. |
| HD-11 | PENDING / user/reviewer | Review this PR-00 and explicitly approve the next scope. Recommended next change is bounded PR-01, not experimental execution. |

No decision has a fabricated human name/signature/date. Existing merge-message phrases such as “independently verified” are author assertions, not substitutes for rater/custodian provenance.

## Stop conditions retained from the roadmap

- If outcome validity fails, stop broad claims and repair measurement before adding experiments.
- If independent targets or authorized models are unavailable, report that limitation; do not synthesize results or labels.
- If only seeded vulnerabilities are demonstrated, report seeded fixture detection, not organic discovery.
- If graph-aware/adaptive arms lose, preserve and report the result.
- If benign utility falls after remediation, report the tradeoff.
- If legacy reproducibility breaks, preserve legacy behavior/evidence before continuing.

**Current stopping point: PR-00 for review.** Any later GO must name the approved scope and satisfy the relevant human gates; merging documentation alone does not grant study execution authority.
