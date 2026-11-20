# DEV Pilot Decision Packet — PR-09 Stage B1

Updated 2026-11-20: the user selected a **candidate defender**, not an approved deployment: `Qwen/Qwen3-4B-Instruct-2507`, quantized as `mlx-community/Qwen3-4B-Instruct-2507-4bit`, revision `50d427756c6b1b2fe0c0a10f67fbda1fc8e82c1b`, with MLX-LM on Apple Silicon. See [candidate refinement](pr09b1_mlx_refinement.md).

**Draft for human decisions. Not an approval, authorization, model selection, or pilot result.** The [machine packet](pr09b1_decision_packet.json) supplies source identities, actual fixture policy/tool schemas and explicit null decisions. [Readiness](pr09b1_readiness.json) remains NO-GO. The finalized master plan and merged Stage A govern.

## Exact proposed target boundary

Repository-authored PR-03 `it-helpdesk` and `document-management`, vulnerable/hardened synthetic variants only. Policy IDs are `fixture.helpdesk-policy` and `fixture.document-policy`, version 1.0; exact source fingerprint is in the machine packet. Available synthetic principals are employee, manager and outsider. No real payments, email, account permissions, network sharing or production effects exist; all effects stay in fresh local SQLite ledgers/inboxes. Different business logic does not establish independent external targets or validity.

The operator must supply actual owner/custodian identities, signed testing scope, independently reviewed policy/reader/finality/reset semantics and deployment ownership. GitHub authorship/merge is not signed ownership. Per-run target IDs, actor, reset authority, scenario, repeat and arm remain bound out of band. No identity or person is assigned by this packet.

Proposed surfaces: direct user text; untrusted data in an actual matched tool response; content from a successful read of an exact synthetic document. For indirect input, approve tool + matching-call ordinal + document, then bind the actual model-generated call ID and consuming request at runtime. No guessed IDs or fabricated retrieval. Multi-surface workflows, externally accessed targets and currently unsupported corpus task surfaces remain visible and unsupported. Review exact payload/legitimate task and anchor in every proposed ModelPlan.

## Decisions to supply before any real request

| Decision | Required human-supplied artifact | Current status |
| --- | --- | --- |
| Model/provider/revision | Exact model ID, immutable weights, server binary/source revision, chat-template hashes, licensing/permission and tool-call capability review | Candidate pinned; no weights provisioned or execution approved |
| Local deployment | Owned server process and signed custody lease binding actual PID, command, endpoint, artifacts, run nonce and plan | Missing |
| DEV cases | Independently reviewed source case identities/family IDs and public common pool; approve surfaces, exclusions and attacker information | Not selected/approved |
| Request/token/time caps | Max turns, all PR-05 dimensions, common arm ceilings, bounded context/output and request/conversation timeouts | Unset |
| Monetary semantics | Currency, pricing identity, worst-case token debit and whether unmeasured actual local hardware spend is acceptable | Unset; no zero-cost assumption |
| Evidence/review | Real policy/state custody, oracle review and independent raters/adjudicator responsibilities, blinded human support where required | Missing |
| Containment | Supervised isolated worker, owned server group kill/reap, OS egress controls, late-effect/finality checks, actual worker/supervisor binding | Unavailable/unreviewed |
| Authority | Genuine externally supplied registry/public keys/roles, independently authenticated bootstrap hash, validity/revocation and signed exact-scope approvals | None supplied |
| Separate DEV GO | Researcher/budget/owner/custody/review approvals, retention/redaction and stop rules | Missing |

No model, revision, budget or family assignment is **approved**. Proposed settings are 4,096 total context tokens (3,584 input with full 512-output reserve), 512 maximum output, temperature 0 without assumed determinism; 8 episodes, at most 4 model requests each (32 total), 30 minutes total batch wall time, and ₹0 paid API spending. MLX-LM/MLX 0.26.2 and Transformers 4.53.3 are pinned to an isolated runtime lock. Compatibility is metadata/source-based, not an executed model test. The prior llama.cpp-family client remains legacy B1 compatibility infrastructure and is not the selected candidate runtime. No weights, model execution or pilot is performed.

## What the approval gate verifies

An externally supplied registry, independently pinned out of band, defines actual entitled public keys and roles. No root, signer, keypair generator, signing command, valid approval fixture or named trusted person is shipped. Ed25519 verification checks domain-separated canonical approval bytes, exact scope/evidence hashes, validity, revocation, role coverage and independent reviewer/adjudicator groups. Evidence files are read and hashed afresh. A merge, key in an environment, JSON claim or hash alone grants nothing. Root provenance is a human trust-bootstrap responsibility; cryptography cannot authenticate who originally supplied a root.

Proposed responsibilities are target owner, principal researcher, budget owner, evidence custodian, two independent reviewers and an adjudicator. These are roles for review, not automatic assignments or fabricated independent labels. Changing the required roles/independence rule needs an explicitly reviewed gate revision. Actual signatures must come from the supplied genuine authorities. No positive authorized-run test can be claimed without those records; tests intentionally cover rejection and public RFC crypto vectors only.

Scope binds exact ModelPlan (identity/model/settings/caps/payload), case pool/corpus/graph, adapter/target/policy source, DEV families/surfaces, protocol, model custody and cancellation evidence. Actual model source and DEP environment must match reviewed provenance. Per-deployment PID-bound evidence requires a controlled provisioning/signing process; no generic reference string or reusable script fixture is accepted in its place. An operator must provision a genuinely reviewed supervised worker/server; B1 supplies no automatic model/server launcher.

## Usage, cancellation and stop requirements

The legacy B1 HTTP client remains numeric-loopback-only. The selected MLX path instead uses a local native request subprocess with all networking/process spawning denied, no Hub resolver, no key discovery, no prompt cache, no draft model and no retries. An existing immutable local snapshot and genuine approvals must be verified before importing MLX or loading weights. Only synthetic PR-03 tools can execute. A model alias is insufficient identity: actual artifact hashes and independently supplied process custody are required. Exact server command/context bounds must be reviewed against the selected binary. The maximum input-token reservation depends on that bounded server context; there is no claim that text length is an exact tokenizer. Missing/unverified native context enforcement must block deployment approval.

Record complete request/response JSON, role/order/call IDs, finish status, reported prompt/output/total tokens, wall time and client retry count. Unknown provider-internal usage/retries remain unknown. Missing tokens, truncation, model mismatch, invalid tool schema, reused call IDs or overages stop before tool dispatch/another request. Incomplete/killed work stays UNKNOWN. Source/consumption receipts do not certify a committed effect; private PR-01/05 packets and later genuine PR-06 review remain necessary.

Token-rate debits use explicit integer ceiling arithmetic and the signed pricing/currency contract. **They are not measured hardware spend or a provider invoice.** Actual hardware/energy spend remains null. For the selected MLX candidate, ₹0 denotes **paid API spending only**; hardware cost is never inferred to be zero. The legacy gate requires the budget owner to explicitly accept its token debit basis; if actual monetary metering is required instead, this adapter is NO-GO until such a meter is integrated. No equal-actual-cost claim follows from equal token debits. Common per-arm ledgers cannot reset between attempts. The bridge measures shared graph/selector preparation once and debits it equally to all arms, then charges measured per-arm selection and conversation time under the PR-07 policy. The budget owner must approve that policy. Model/server provisioning and hardware overhead still need separate measurement; software wire fixtures do not establish their real cost.

Local server deadlines terminate/reap the caller-owned group. A real pilot additionally needs a separately supervised agent worker and independently verified OS egress/cancellation/finality controls; API timeout alone is insufficient. This PR has not validated a model server, supervisor or escaped-native-code containment. The gate checks supplied worker/PID/source review records but cannot replace their genuine independent review. Missing containment evidence keeps calls disabled.

Stop on revoked/expired approval, changed source/artifact/custody, reset failure, audit incompleteness, unknown usage, exceeded budget, unexpected model/tool/endpoint, containment failure or unapproved deviation. Archive missing/failed/unsupported attempts; no silent retry. All raw and private evidence needs an approved retention/redaction policy before a genuine pilot.

## Four arms and next milestone

PR-07 Strategy remains the selector: graph only for A2/A4, ordinary response feedback only for A3/A4, no private oracle/policy/state/reviewer information. The target model receives only public messages/tools; it does not receive arm/graph annotations. Versioned v2 ordinary-model feedback avoids calling a real response a test double. A1/A2/A3/A4 use the same public pool, identities/policies, reset and approved global arm ceilings. Current matching is infrastructure, not an empirical fairness finding. Unsupported opportunities remain in inventory; no success denominator is computed.

A2−A1 remains primary. Proposed A4−A1 is pending approval; PyRIT remains exploratory/unapproved for equivalence. TEST remains unassigned/unfrozen. No statistical effects, power estimates or PR-10 work are performed.

The next milestone is a **separately authorized, small genuine DEV pilot**: provision the selected immutable local model/server under reviewed supervision, supply genuine authority/evidence/budget/case records, verify prerequisites offline, obtain explicit DEV GO, then execute and independently check the bounded raw evidence. B1 does not authorize or execute that milestone. If deployment compatibility, metering or containment cannot meet the signed decisions, report NO-GO instead of replacing the pilot with scripted success.
