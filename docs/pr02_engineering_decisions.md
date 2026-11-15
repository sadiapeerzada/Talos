# PR-02 decision boundary

Date: 2026-11-15. Base: `2ab0d711259eb94ad3807c6eaebeb776cc7e1843`, confirmed remote main after PR-01 #15 merged. Dedicated branch: `research/pr-02-portable-profiles`. Original user changes remain in their original checkout. This ledger precedes implementation; it does not assert researcher approval of a target, policy or trust source.

| Decision | Status | Engineering treatment |
|---|---|---|
| Target ownership, independent custody/authorship and metadata accuracy | BLOCKED for empirical claims: no independently validated new targets supplied. | Profiles carry custody declarations and evidence references; examples are synthetic tests, never independent targets or results. |
| Authorization contracts, identity/consent and boundary exceptions | BLOCKED for operational authorization: PR-01 decisions remain open. | Store explicit boundary IDs and versioned rule references. Missing/conflicting permission remains UNKNOWN. Profile declarations cannot decide ALLOWED; an explicit PR-01 policy delegate is required. |
| Which audit/state sources are independently trusted, complete and semantically valid? | BLOCKED for confirmation: researcher must review source custody, finality, rollback and witness meaning. | Profiles describe capabilities and their provenance, but never populate the oracle's trusted-source allowlist or supply a production evidence reader. |
| Are declared flows or supplied call orders proof of data flow/reachability/impact? | INFERRED conservative engineering rule: no. | Separate possible schema/declaration relationships from observed call order, retain source/event/context references, and make neither imply committed effects. Observed traces remain unauthenticated input evidence. |
| Do tool names or missing annotations imply permissions/read-only behavior? | INFERRED conservative engineering rule: no. | New classification uses explicit semantic claims and provenance; names/descriptions do not grant semantics. Absent, unresolved or contradictory metadata abstains. |
| New risk metric, independent validation and equal-budget trial protocol | BLOCKED / outside PR-02. | No numeric metric, study authorization or efficacy claim. Profiles/graph digests and evidence support future controlled graph-aware/graph-blind comparisons, not present performance conclusions. |

The user authorizes bounded engineering, offline regression tests and a PR. No inference, external scans, new attack evaluations, historical edits, manuscript changes or PR-03 work is included. Legacy graph/scorer paths remain unchanged; new APIs are opt-in.
