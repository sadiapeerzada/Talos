# Benign-only policy implementation readiness

2026-11-26. **Engineering: GO for source review. Operational benign: NO-GO. DEV injection: NO-GO. Main A1–A4: NO-GO.**

Implemented the separately approved `talos.local-benign-dev-authorization.v1` design. No actual activation/run approval, authority/key/signature, independent reviewer or production deployment is created. The original seven-role verifier is byte-identical; no compatibility fallback is available to injection or campaign plans.

## Genuinely verified

- **1,154 offline tests passed**, one existing Starlette/httpx deprecation warning, 91.82 seconds on pinned CPython 3.13.7. This includes all prior 1,102 controls and 52 new authorization/scope/privacy/supervision controls. Public RFC verification smoke, schema serialization and diff checks passed. A prior pre-final-privacy full run passed 1,152; the complete final run includes archive binding and exact-prompt capture. No inference occurs in these tests.
- The canonical process-scoped profile actually denied fresh private-file reads, symlink reads, outside writes, IPv4/IPv6 TCP/UDP, fork, subprocess and `posix_spawn` with `EPERM`; explicit public read and scratch write succeeded.
- Pinned MLX/Metal worked under the profile using only `[1,2,3]+1 → [2,3,4]`. No MLX-LM model or checkpoint was loaded. The failure diagnosis/root-anchor correction and earlier profile failures remain in local evidence.
- Combined profile, pre-payload registration and non-model MLX checks passed normal completion, request timeout, coordinator crash, supervisor deadline and supervisor crash. Observed request workers stopped and owned direct children were reaped. Offline tests also cover explicit cancellation and rejected registration/blocked input. This is single-process-failure coverage, not a universal process/kernel guarantee.
- Exact private archive scope is enforced before writes. New live compatibility receipts must preserve exact rendered input/token IDs and their hashes, addressing the earlier sorted-JSON/input-identity issue without changing the input itself. Lightweight replay checks those records' integrity/counts; independent validity still requires actual custody/review.

[Implementation/approval contract and limits](local_benign_policy.md), [default-disabled identity](local_benign_policy_readiness.json), [actual non-model observations](local_benign_policy_verification.json). Detailed raw profiles, logs, PIDs and failures are kept locally under `.talos-benign-policy-verification/`; they are not real authority records or independent labels. Hosted CI, if run, is a commit-specific review record and is not inferred from these local passes.

## Still blocked

1. **Actual authenticated ownership/delegation and resource entitlement:** no real authority assignment, authenticated separate registry/bootstrap hash or external entitlement evidence is supplied. Implementation approval is not proof of ownership or authority to run.
2. **Genuine scope-bound run signatures:** no approved actual plan/scope/nonce, runtime/protocol/custody records, retention/access decision, exclusive ledger or real coordinator/supervisor custody is supplied. Budget/cleanup/ledger staging requires genuine decisions; time is not reset while approvals are collected.
3. **Deployment acceptance:** the macOS prototype uses deprecated/private interfaces, exposes metadata/system IPC beyond tested operations, and depends on an approved trusted coordinator. Actual scope/profile/source/host-bound OS reports and real owner/deployment acceptance are missing. If stronger App Sandbox, simultaneous supervisor+coordinator failure, hostile administrator or kernel/driver/GPU-late-effect guarantees are required, those remain technical blockers, not waived controls.
4. **First real run under this new path:** deliberately NOT EXECUTED. Positive genuine-authorization verification and full Qwen execution under the final signed deployment cannot be claimed without genuine records and a separate explicit run authorization. Non-model Metal success and prior standalone Qwen generation do not grant that authorization.

All original five local user files, checkpoint assets, compatibility evidence and historical research records are preserved. No system-wide security setting/service/binary-signing change, DEV pilot, TEST experiment, statistical protocol change, PR-10 or manuscript work occurred. Stop for review; do not activate the policy or run a model automatically.
