# PR-08 engineering GO / study NO-GO

2026-11-19. Base: latest fetched remote main `cdcab80d2a8bbbe2b88ad9b7dda86397898f49c6`, merged PR-07 #22. Work is on isolated branch `research/pr-08-external-comparator`; the original dirty main checkout is preserved.

**GO for bounded engineering review. NO-GO for operational comparison or empirical claims.** PyRIT 1.2.1 native orchestration is integrated and exercised offline. No provider runner is enabled. No independent comparator effectiveness, fair attack denominator, human label, held-out cohort or generalization result is claimed.

## Validation

- Original baseline: 688 passing offline tests.
- Final full suite: 767 passing offline tests (79 new comparator controls), one existing Starlette/httpx deprecation warning. Python 3.13.7, pytest 9.1.1. The initial full-suite collection exposed a new helper import error; it was corrected to the repository's relative import convention before the passing run.
- Authentic installed upstream smoke: two adversarial callbacks and two objective callbacks. Second adversarial request exactly received the first objective response. Both native local diagnostic scores retained; native outcome `success`, normalized security outcome UNKNOWN, primary count null. Fixed scripts are test doubles, not adversarial model inference.
- Native smoke measured initialization 1,900 ms and execution 115 ms (whole worker 2,395 ms) on this machine. Timing is a single engineering observation, not an experiment or framework performance comparison.
- Complete native archive/replay control: one OFFLINE_NATIVE_CONTROL, two SURFACE_UNSUPPORTED, all three UNKNOWN. Actual callback debits 2 attacker/2 objective, one attempt, whole worker 2,269 ms. Seal `67e93c0f2e4a9755c345d186983debcc2837c467a4911a82b70545ffff20a992`. Local ephemeral archive `/tmp/pr08-real-native-archive-complete`; no historical result artifact changed.
- Separate intentionally undersized 2-second total timeout produced ERROR plus two BUDGET_STOP cells, null missing request usage and no favorable finding. Preserved rather than retried as a success.
- Regression controls include forbidden configuration/provider/plugin settings, credential stripping, source/version identity, domain mappings, missing/duplicate opportunities, policy/actor/profile mismatches, unequal budget dimensions, absent usage, evidence faults, tampered and semantically forged sealed archives, native trace conversion and prevention of fabricated CONFIRMED outcomes. Existing disabled-detector sentinel remains in the full suite.
- 189 prior tracked files and all five original modified/untracked user files matched captured SHA-256 baselines. No existing code, historical corpus/results, manuscript or dependencies were modified. All changes are additive.
- Hosted CI: existing full research matrix (Python 3.11/3.12), legacy workflow and new isolated native comparator matrix are required. Exact runs/results are recorded in the PR after execution; this document does not predeclare hosted success.

## Unresolved human decisions and implementation limits

The [decision ledger](pr08_decisions.md), [suitability report](pr08_suitability.md) and [integration contract](pr08_integration.md) enumerate the gates. Researchers must approve external comparator validity, objectives/opportunities and surface equivalence; actual target delivery/custody, actors/policies/reset semantics; independent PR-06 adjudication; allowed attacker information and native adaptive/static configuration; provider/model/seed assumptions; full usage/currency/initialization/graph overhead accounting; denominators and case/target clustering.

Existing A2−A1 remains primary. Proposed A4−A1 and an external-framework contrast are explicitly pending approval. Native substring grading is not the evidence-aware oracle. Shared objective input is not proven equivalent to Talos corpus prompts; native stubs do not validate real model generation. Unsupported indirect/workflow cases are retained and cannot enter a favorable delivered-only denominator. Actual provider/agent/tool usage is unmeasured and null; operational matching is blocked even when ceilings match.

The worker uses application controls for trusted pinned code, not an OS sandbox. Reproducibility covers pinned identities, traces and semantic replay; native UUIDs/timestamps and hypothetical stochastic models need not repeat. Source-only dependency building uses pinned backends in an isolated environment. These are researcher-controlled synthetic controls, not independently validated external targets. No PR-09 implementation, live inference, scans, empirical attack sweep or manuscript work was performed.
