# PR-09 Stage A engineering review and empirical NO-GO

2026-11-19. PR-08 #23 verified merged. Base/latest fetched remote main: `700d6acf9c06e98c82cd623abf17c65c301ef24d`. Dedicated branch `research/pr-09-stage-a-readiness`; original dirty main checkout preserved. Final experimental master plan v1.0 and original roadmap remain authoritative.

**PR-09 EMPIRICAL EXECUTION: NO-GO.** Stage A prepares reviewable engineering interfaces, controlled offline workflows and study-freeze artifacts. It does not complete PR-09's experimental phase. There was no approved DEV pilot or campaign, no independent validation result, no TEST selection/freeze, and no provider inference.

## Deliverables and status

- [Machine-readable readiness report](pr09_readiness.json): fourteen gates, each with evidence, approval authority, status and reason. None is approved by a merge/configuration string. External approval verification and provider transport remain unavailable.
- [Pre-implementation decision ledger](pr09_stage_a_decisions.md): specific missing researcher/owner/reviewer/budget decisions, recorded before implementation.
- [Controlled delivery/capability contract](pr09_delivery_contract.md): distinct direct-user, tool-output and retrieved-document insertion with exact source/consumption identity; unsupported and unconsumed surfaces explicit. Actual local tool workflows use fixed offline replies, never masquerading as model-backed experimental attacks.
- New isolated worker, hard process-group kill/reap, network/process denial, private PR-01/05 packets, failed-reset fences, exact counters, spending/usage receipt contracts, exclusive archives and recorded-only replay. All actual provider usage and independent primary findings remain null.
- [Prospective protocol draft](pr09_protocol_draft.md) and [freeze preparation manifest](pr09_freeze_preparation.json): targets/custody, DEV/TEST independence, root causes/units, A1–A4, information/feedback, budgets/stopping, paired cluster analysis/interval proposals and missing observations. Existing A2−A1 primary preserved; A4−A1 secondary and exploratory PyRIT equivalence pending approval. No statistical analysis/PR-10 implementation.

## Offline validation and custody

Baseline: 767 passing tests from merged PR-08. Stage A adds 132 regression controls. Final full suite: **899 passed**, one pre-existing Starlette/httpx dependency deprecation warning. Exact timing and final-head hosted CI links/results are recorded in the PR after execution.

Tests cover two fixture domains and both vulnerable/hardened variants; direct, tool-output and document delivery; exact injection anchors and missing consumption; real synthetic actions and unchanged five-way oracle; authorized tasks; failed/rolled-back/delayed/missing/contradictory state evidence; failed/incomplete resets; hard cancellation and child reaping; network/process denial; credential isolation; budget exhaustion; invalid/duplicate/mismatched provider usage receipts and overages; fresh cross-arm stores/no shared history; private-oracle isolation; forged approvals/cohorts/freeze/primary results; tampered/resealed archives and rewritten message histories/tool schemas/budget counters. Scripted success text alone creates no finding.

Full local command, worktree `/tmp/talos-pr09`, existing Python 3.13.7 / pytest 9.1.1:

```sh
env -u ANTHROPIC_API_KEY -u GROQ_API_KEY -u OPENAI_API_KEY -u LANGSMITH_API_KEY -u LANGCHAIN_API_KEY -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY LANGSMITH_TRACING=false TALOS_RESEARCH_TEST_STATE_DIR=/tmp/talos-pr09-final-state PYTHONPATH=/tmp/talos-pr09/talos/tests/offline_support:/tmp/talos-pr09/talos /Users/sadiapeerzada/Talos/talos/.venv/bin/python -m pytest talos/tests/ -v
```

All prior 209 tracked files and all five original modified/untracked user files matched captured SHA-256 baselines. Existing CLI/dashboard, historical Talos-35/raw results, legacy scoring, all PR-01–08 contracts, independent references and dependency locks remain unchanged. Changes are additive. Existing full research/legacy/comparator CI plus new readiness artifact/control jobs run on the PR; passing engineering CI is not study approval.

## Blocking decisions and honest limits

No signed target ownership/testing scope, independently approved policies/trusted readers/finality, operational delivery review, authenticated authority registry/signature/expiry/revocation verifier, model/provider/account consent, actual monetary/token/request budget, provider usage/billing/cancellation adapter, independently validated corpus/TEST cohort, independent raters/adjudicator or frozen statistical protocol was supplied. These block actual model calls and the DEV pilot. Choosing them in code would invent approval. Keys, references, hashes and merged PRs confer no authority.

The executable agent backend is an explicit reply script, not an LLM. Real synthetic tool effects/private fixture CONFIRMED labels remain non-primary engineering controls. Source/consumption receipts prove this offline boundary, not genuine provider consumption or independent validity. Application guards/process groups are not an OS sandbox. Hard kill can leave usage/evidence incomplete and scheduling/cleanup overhead measurable; the whole episode stays UNKNOWN. Remote provider finality, late billing/effects and production containment remain unverified. ProviderLedger validates supplied receipt consistency, not authenticity or actual captured usage. No live transport is enabled.

Fresh stores preserve isolation but their UUIDs and timings vary. No reproducibility of hypothetical stochastic provider outputs is claimed. Too few independently controlled domains/clusters may force descriptive claims later. No broad transfer, security advantage, effect size, successful empirical discovery, reviewed delivery approval or independent human label is claimed.

**GO for Stage A engineering review only. PR-09 experimental completion remains false.** Stop for review; no PR-10, external scans, campaigns, manuscript, figures or publication work.
