# PR-09 Stage A controlled delivery and capability contract

Version `talos.controlled-delivery.v1`. This is proposed for independent review. No independent delivery approval, model permission or empirical validity is asserted. PR-09 EMPIRICAL EXECUTION: NO-GO.

## What executes

The new `talos.readiness` package is separate from legacy CLI/dashboard, PR-05 fixture controls, PR-07 scheduling and PR-08 native comparator controls. `EngineeringPlan` only permits DEV, explicit offline replies and two local PR-03 domains. It stores source/environment provenance, actor/run/scenario/repeat/arm, legitimate task, injection anchor, reset/tool faults, strict PR-05 limits and hard timeout. No arbitrary Python callable, endpoint, SDK or live model identity is accepted. Invalid extra/private fields fail validation.

`execute(plan, new_archive)` spawns a fresh isolated Python worker with `-I`, a known source root, fresh working/TMPDIR, cleared credentials/configuration/proxies, no global learning and default-deny DNS/socket/process execution. The only model backend is a bounded list of data-only replies. Those replies drive actual PR-03 tool execution and deterministic synthetic stores. They are agent-workflow engineering controls, not an LLM-backed target, completed prompt-injection attack or independent experimental result. Each call receives an operator-bound actor/reset scope; arguments cannot replace identity. Unknown tools cannot access the reader or controller.

## Distinct surfaces and observable delivery

| Surface | Insertion | Necessary recorded consumption |
| --- | --- | --- |
| `direct_user` | Exact input becomes a user-role message after the legitimate task | A subsequent model-boundary request includes that exact message |
| `tool_output` | An exact real tool/call response receives an explicit untrusted-data field | Real action anchor plus next model request containing the hashed tool message |
| `retrieved_document` | Successful `read_document` of an exact document supplies its content at the tool boundary | Matching call/action/document and next model request containing the replaced content |
| `unsupported_workflow` / other unspecified surfaces | Not delivered | Explicit UNSUPPORTED, never simulated as an attack |

Receipts bind plan hash, target, actor/arm/run/scenario/repeat, authorization context, payload, original content identity, delivered message hash/index and consuming request. No tool response is invented when an anchor is absent or retrieval fails. A final insertion without another model request is DELIVERY_UNCONSUMED. A model's success claim does not prove a tool action, effect or security violation. The receipt verifies this implementation's offline message boundary; genuine provider consumption and independent review remain missing.

Tool schemas and ordinary messages alone enter the agent boundary. Private policy, audit, snapshots, PR-01 verdicts and other-arm state stay out. This target-agent workflow is common across arm identifiers; it does not implement a new attacker selector or demonstrate graph/adaptation effects. PR-07 attacker information/scheduler contracts remain authoritative and operational integration awaits approval.

## State, oracle and independent primary eligibility

Every tool call produces its real PR-03 observation and exact action binding. The controller reads policy and state/audit independently from the agent-visible response, captures reader issues/raw provenance, and builds PR-05 `Packet` records. Unchanged PR-01 `judge()` and PR-05 `replay_packet()` evaluate them. Failed/incomplete resets fence all calls. Real synthetic tool outcomes can be CONFIRMED, ATTEMPTED, BLOCKED, NO_VIOLATION or UNKNOWN; these private fixture verdicts never become independent discoveries.

The Stage A episode's unified empirical outcome is always UNKNOWN, primary eligibility false, independent findings null and actual provider usage null. Actual independent PR-06 rater/custody/root-cause approval remains required. Authorized tasks have separate tests across both domains and hardened/vulnerable variants; passing them is not empirical utility evidence.

## Hard cancellation and budget semantics

A POSIX child starts in its own process group. The parent enforces the smaller of explicit hard timeout and wall-time ceiling from before launch. Expiry kills the process group and reaps the process; the temporary working/store tree is cleaned. Keyboard/exception paths also terminate/reap the child. A killed/failed child's partial tool/evidence usage is unavailable, not zero; no retry or resume occurs. The sealed record is HARD_TIMEOUT or FAILED with UNKNOWN and `usage_complete=false`. Incomplete archives also remain invalid for completed claims.

This contains the shipped trusted Python scripts and local synchronous stores. It is **not an OS sandbox**, a guarantee against hostile native code, or cancellation of a real remote provider/billing operation. Remote cancellation, late effects, finality and authenticated custody are unresolved operational gates. Scheduling and cleanup can add measurable wall-time overhead around a kill; actual whole-worker time is retained. No late child tool invocation can occur after verified local process exit. No production side effects are available.

PR-05 budgets enforce one episode attempt, each scripted agent request (`target_model_calls` control debits) and each real synthetic tool call (`target_calls`). These are explicitly test-double accounting units, not actual provider measurements. Whole-worker time is charged to elapsed usage; overruns are recorded. Exhaustion stops the next interaction; unsupported/unconsumed/failed work is retained. Metadata never supplies a monetary approval.

`ProviderUsage` requires explicit model/revision, input/output tokens, retries, cost/currency, price schedule and provider-receipt identity. `ProviderLedger` reserves worst-case dimensions before a hypothetical request and settles supplied receipts, rejecting missing/mismatched/reused receipts and overages before another reservation. It validates consistency, not receipt authenticity or real billing. No transport/inference capability is supplied by a ledger. Operational usage capture/billing reconciliation still requires an approved provider adapter and independent custody.

## Approval and credentials boundary

`CapabilityRequest` defines explicit opt-in, target/profile/policy/reset/protocol/delivery identities, DEV scope, exact model/revision/sampling, network policy, all resource caps and a private credential handle. The handle is excluded from serialization and representation. Provider keys in the environment cannot activate the worker or live calls. Operational invocation always raises NO-GO.

`ApprovalClaim` records claimed signer, evidence/scope identity, expiry and signature; none is treated as valid by declaration. `ApprovalVerifier` describes an external trust-root interface, but no concrete operational authority registry, authenticated signature/expiry/revocation verifier or provider transport is installed. Even a plausible signed-looking claim or merged PR remains UNVERIFIED. Selecting the real authority/custody/signature and provider contracts without researcher input would invent an approval; these are explicit blockers rather than unsafe permissive defaults.

PR-05 `NetworkPolicy` supplies prospective exact-origin/pinned-resolution/redirect checks; no HTTP transport exists in this path. Actual destination allowlists and ownership are not inferred from strings. The CLI exposes only report, schema and replay. There is no live/pilot/freeze command. Nothing can access TEST or assign reviewers.

## Replay and provenance

PR-05 exclusive content-addressed recording stores manifest/readiness, intent, result and complete summary with an expected seal. Replay never calls providers or tools. It validates plan/arm/reset/action identity, explicit script consistency, receipt insertion/consumption, private oracle packets, counters and primary/missingness integrity. Rehashing altered bytes does not excuse semantic inconsistency. Hashes establish content consistency, not independent truth, signatures or permission. Provider secrets are never taken as model inputs or logged; arbitrary sensitive user content still requires a future reviewed redaction/retention plan.

All prior tracked files and original local work are preserved. No dependency changes are required. Runtime process-group containment requires POSIX (tested Darwin, CI Linux); other platforms are not silently given weaker cancellation.
