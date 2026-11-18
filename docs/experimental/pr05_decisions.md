# PR-05 pre-implementation decisions

2026-11-18. PR-04 #19 verified merged at 8fa20f4fc718bea8694e11f7c9962d7969f13c74, latest fetched main. Final experimental master plan v1.0 and merged PR-00–04 govern this bounded engineering phase.

- No study, DEV/TEST cohort, external endpoint, model, trusted source or policy approval is selected here. Explicit operator declarations are recorded, not authenticated human approvals. Synthetic regression declarations are labeled test-only.
- Direct deterministic fixture controls test the recorder/oracle; they are never reported as delivered prompt-injection cases. Corpus delivery remains unavailable and UNKNOWN until a real reviewed adapter exists.
- No model or HTTP transport implementation is enabled. API keys and global learning are never consulted. Network policy validates proposed destinations conservatively, but does not authorize or send requests.
- Run-scoped append-only files, hashes and chains establish consistency under filesystem custody, not signatures or protection against a malicious OS owner. A pinned seal/head is needed to detect wholesale archive replacement/truncation.
- Persist intent before side effects. Interrupted intent is indeterminate; recovery never retries/substitutes it. Missing cells remain UNKNOWN with explicit stop reasons. Recovery finalizes the existing ledger without executing new calls.
- Synchronous local fixtures have cooperative timeout/elapsed accounting, not forcible process termination. Overruns are explicit non-confirmations; hard process containment remains required before unbounded adapters.
- Strict preflight budgets reserve declared ceilings; actual overages/missing usage close the ledger rather than permitting further calls. No invented token/cost/model measurements.
- Learning is disabled or an explicit immutable supplied snapshot; no global SQLite read. Source/dependency/configuration identities are recorded. A dependency lock and hosted compatibility checks do not constitute an approved empirical environment freeze.
- CI uses positive/negative/UNKNOWN outcome controls and an intentionally disabled-detector sentinel, independently of unchanged historical risk scoring.

Unresolved operational gates: source custody/finality and reviewed policy; adapter semantics; true hard timeout/isolation for future providers; unit/denominator/root-cause clustering; permitted feedback/information, budgets, split freeze, human labels and licensing. None blocks offline framework engineering. No PR-06 is authorized.
