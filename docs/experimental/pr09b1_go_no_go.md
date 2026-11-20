# PR-09 Stage B1 engineering GO / operational DEV NO-GO

**2026-11-20 continuation:** the user selected a Qwen/MLX defender candidate and proposed caps. [Refinement record](pr09b1_mlx_refinement.md) supersedes the initial unselected-model field below; all initial B1 results remain historical engineering results. Actual deployment, authority/custody approval and model inference remain absent. No new PR is authorized or opened.

2026-11-19. Base: latest fetched remote main `5d8df487794212d2bfdf63afb3c8cf3a562dc705`, merged Stage A PR #24. Dedicated branch/worktree preserves original user files. Final experimental master plan v1.0, original roadmap and merged PR-00–Stage A govern.

**Engineering GO for bounded component review. Operational DEV pilot: NO-GO. Inference disabled; no pilot executed; PR-09 experimental completion false.**

## Delivered

- [Pre-implementation audit/decisions](pr09b1_audit_decisions.md) identifies what Stage A lacked and what remains genuinely unavailable.
- [DEV Pilot Decision Packet](pr09b1_decision_packet.md) and [machine packet](pr09b1_decision_packet.json) contain actual fixture policy/tool/source identities, proposed scopes, responsibility/evidence requirements and explicit null owner/model/case/budget/approval decisions. No held-out selection/freeze.
- [Adapter contract](pr09b1_adapter_contract.md), real default-disabled loopback client, strict model/tool conversion, exact artifact/custody binding, raw request/response receipts, integer token/debit accounting, missing-usage stop, owned-process cancellation and recorded-only replay.
- Stage A delivery hook reuses the same actual synthetic stores, operator-bound identities, private PR-01/05 packets and insertion/consumption paths. Existing script defaults preserved. PR-07 adds a versioned ordinary-model feedback source while retaining v1 defaults; the same Strategy supplies all four arms. Graph/private oracle/policy/state metadata stays out of target-model requests. Shared arm ledgers cannot reset; measured preparation is equally debited, selection and conversation time charged separately.
- Explicit optional Ed25519 verifier for **externally supplied** authority registry, independent bootstrap, exact scope/evidence, validity/revocation, role/group/key separation. No keys, trusted identities, generated signatures or valid approval fixtures are supplied. Public RFC verification vectors test crypto, not approval or reviewer validity.
- Machine [readiness](pr09b1_readiness.json) and a new offline CI matrix with optional hash-pinned crypto. Existing research/dependency locks and legacy execution defaults remain intact.

## Verification and custody

Merged Stage A baseline: 899 tests. B1 adds 92 offline software regressions. Full local suite: **991 passed**, one existing Starlette/httpx deprecation warning; focused B1: **92 passed**. Public RFC 8032 Ed25519 vector verification and wrong-message rejection passed in the separate pinned environment. Final full timing and hosted job links/counts are recorded in the PR after completion.

Controls cover conversion, exact model label and IDs, duplicate/nonfinite JSON, unknown tools/arguments, refusal/truncation/missing/invalid tokens, all three surfaces in both domains/variants, real synthetic effect evidence and blocked outcomes, unconsumed delivery, missing usage/cost distinction, per-arm budget persistence/exhaustion/preparation, fresh contexts, private metadata isolation, invalid/missing/expired records, no environment-key activation, owned non-model test-process cancellation/reaping, and tampered/semantically inconsistent sealed records. Fixed wire records are not empirical validation data or actual provider measurements. No genuine positive authorized bundle exists; no positive live gate/model/deployment compatibility test is claimed.

Existing Python 3.13.7 baseline environment was not modified. A new `/tmp/talos-pr09b1-venv` installed hash-pinned research + separate optional verifier locks. Full offline command from `/tmp/talos-pr09b1`:

```sh
env -u ANTHROPIC_API_KEY -u GROQ_API_KEY -u OPENAI_API_KEY -u LANGSMITH_API_KEY -u LANGCHAIN_API_KEY -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY LANGSMITH_TRACING=false TALOS_RESEARCH_TEST_STATE_DIR=/tmp/talos-pr09b1-reviewed-state PYTHONPATH=/tmp/talos-pr09b1/talos/tests/offline_support:/tmp/talos-pr09b1/talos /tmp/talos-pr09b1-venv/bin/python -m pytest talos/tests/ -v
```

Of 230 pre-existing tracked files, only `readiness/agent.py` (explicit backend hook) and `ablation/contracts.py` (backward-compatible feedback version/source) change. The other 228 match captured SHA-256 baselines. All five original local modified/untracked user files remain byte-identical and excluded. Historical Talos-35/results, original research evidence, scoring, manuscripts, CLI/dashboard and existing test files remain unchanged.

## Blocking decisions / deployment requirements

No genuine trust-root/authority records, signed scope, actual owner/custodian/reviewer identities, selected model/server/template revisions/artifacts, reviewed DEV families/surfaces, numerical caps/pricing/actual-spend policy, owned server custody, supervised isolated worker/OS egress/cancellation proof or separate DEV GO were supplied. B1 does not provision a model/server or operational supervisor. A genuine deployment must meet these contracts and independent review; a metadata declaration or successful unit test cannot substitute.

Actual server context/tool-template behavior, reported usage completeness, process cancellation/late effects, OS containment and independent outcome validity remain unverified. The gate requires actual reviewed deployment/custody records before connection, but cannot authenticate a trust root's human origin or prove independence from strings. Operator bootstrap/independent review are indispensable. App guards and process groups are not an OS sandbox. The local budget uses explicit conservative token-rate debits; actual hardware spend remains null. If a measured-spend policy is required, an actual meter is additional required engineering, not an inferred zero.

The current scope/lease scheme requires exact per-run deployment/worker identity and external signing/provisioning; B1 does not claim automated batch deployment or inexpensive approval workflow. Incomplete/killed work lacks complete partial evidence and remains UNKNOWN. No fairness, detector validity, graph advantage, cross-domain transfer, real LLM capability or empirical superiority follows from these tests. A2−A1 stays primary; proposed A4−A1/external equivalence remain unapproved.

Stop for Stage B1 review. The next milestone is a separately authorized small real DEV pilot with independently checkable raw evidence. Do not replace it with another scripted success report. No inference, model-server launch, external scan, pilot/campaign, TEST freeze, fabricated human labels/approvals, PR-10 or manuscript/publication work occurred.
