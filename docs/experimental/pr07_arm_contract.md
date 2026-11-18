# PR-07 four-arm experimental framework

**Engineering only. Operational study BLOCKED.** PR-05 has no corpus prompt-delivery adapter; PR-06 has no genuine independently supplied human labels or approved operational source custody. This framework does not bypass either gate. It cannot execute real targets, tools or models. Scheduler test doubles are not experimental attacks or delivered prompt injection.

Governing context: final experimental master plan v1.0, original roadmap and merged PR-00–06. PR-06 #21 merge/base `b5f70f49e56390dd110432f7ae0b605fe2dcb6b1` was verified on fetched main. Existing source, CLI/dashboard, oracle, scorer, raw findings and dependency/CI environment remain unchanged.

## One implementation, two switches

| Arm | Graph view | Outcome-conditioned update | Shared implementation |
|---|---|---|---|
| A1 blind/static | None | None | `Strategy`, frozen public-priority selector v1 |
| A2 graph/static | PR-04 possible topology only | None | Same selector, graph switch |
| A3 blind/adaptive | None | Completed ordinary feedback only | Same selector, adaptation switch |
| A4 graph/adaptive | PR-04 possible topology only | Same feedback rule | Same selector, both switches |

All arms use the same pool, public tool inventory/schemas, immutable stimuli, selector version, seed, request ceilings, reset contract, utility controls and public feedback rule. Only graph visibility and adaptation differ. The plan accepts exactly A1–A4 and one common `Limits`; per-arm budget/policy overrides are forbidden. A5 generic mutation/A6 model-guided arms and external comparators remain deferred, not represented as completed.

Selector v1 is a transparent engineering baseline, not an optimal or independently validated attacker. It ranks public opportunities by the number of permitted possible data-flow edges whose endpoint tools both appear in the public stimulus, with seeded stable-hash ties. Blind arms have no graph score. Static selection cycles a frozen order independently of target responses. Adaptive selection uses the same frozen order as its base; bounded priority weights can change only from explicitly permitted public tool mentions following a completed attempt. Visits/slot counters are bookkeeping and do not add outcome rewards. Without feedback, corresponding static/adaptive arms have the same selection sequence.

Feedback v1 consists only of ordinary response text and referenced public tool names, with a test-double provenance marker. It never includes PR-01 verdicts, true policy decisions, evidence-reader state, held-out expectations, private observer packets or another arm's state. Weight updates count mentioned tools in public candidate stimuli, not success/denial/CONFIRMED words. Unknown referenced tools, extra private fields and structured private-label JSON are rejected. Arbitrary free text can still reveal hidden data; real adapter feedback filtering and information policy require review. This is not a Python/process sandbox against a malicious coordinator.

Every strategy has versioned state with an owner hash bound to arm, block scope, pool and seed. State includes slot, visits, weights and update count. Full before/after updates and permitted feedback are recorded. Cross-arm/block state imports and stale choices fail. The selector receives only `PublicView`, never the private Plan/profile/utility classification, scripts or observer evidence. Public inputs are copied/revalidated so ordinary nested mutations are not shared across arms.

## Common opportunities and delivery scope

`corpus_block` prepares only explicitly supplied PR-04 binding IDs and retains per-case actual and hypothetical applicability. Actual default surface availability remains UNKNOWN. A hypothetical all-surface contract exists solely to render planning-compatible public opportunities for data-only scheduler tests. Missing/conflicting roles/permissions or incompatible tools remain UNKNOWN/INAPPLICABLE and cannot silently become safe. They are retained in preparation counts and reasons even when absent from the planning pool.

Each block carries one PR-04 `CommonPool`. All contained public tool names/descriptions/input/output schemas must exactly match the same PR-02 profile. Underlying content and eligibility are decided once, before any arm sees graph data. Graph awareness cannot add/drop cases or change stimuli. Aware views receive only `project_possible_graph(build_profile_graph(profile))`: possible invocation/data-flow topology, no observed paths, policy/evidence labels or execution references. Blind views retain identical inventory/schemas without topology. Empty planning pools produce explicit unsupported slots, not clean outcomes.

Explicit legitimate-task IDs are a subset of that same public pool. They are private controller metadata, not selector labels. After the common number of selection slots, each arm gets the same fixed utility slots. Utility feedback never updates attack selection. They use the same per-arm block budget and remain missing if the budget/timeout stops earlier work. An attack selector can choose the same public text earlier; no opportunity is privately withheld from one arm.

No DEV/TEST cohort is selected. `cohort_status` is always UNASSIGNED. Public synthetic fixture data do not establish held-out validity or target independence.

## Matched ordering and reset isolation

One declared seed shuffles A1–A4, then cyclic rotations balance positions across successive matched blocks. Four blocks give each arm each position once; incomplete groups retain the declared rotation without claiming perfect balance. The serialized schedule includes the common-pool hash and reset contract. Replay rejects reorder/interleaving, changed opportunities and duplicate/missing cells.

Each arm/block starts with fresh adaptation state and a fresh data-only session. Before every simulated dispatch, reset returns a deterministic unique scope bound to comparison, block, arm, slot and seed and increments its own generation. A failed reset prevents dispatch. No prior arm/session is consulted, no SQLite learning state is read and no API key or provider availability changes behavior. Test-double scripts are immutable data keyed by public opportunity ID, not arm, and the same response/accounting fixture applies whenever any arm selects that opportunity.

This validates scheduler/reset bookkeeping only. It is not a PR-03 store reset, a real agent state transition or proof that future adapters isolate actual targets. Real reset/identity/cancellation contracts still require reviewed delivery infrastructure.

## Budget and overhead policy

`talos.factorial-accounting.v1` is an explicit proposed **matched information-ablation** accounting policy:

1. Reserve shared preparation before computing topology/public views. Measure local common preparation once, including graph projection, and record its actual physical count/time. Charge the same measured amount to every arm's block ledger as a matched debit. This is four equal accounting charges, **not a claim of four physical builds**.
2. Before every simulated selection/utility attempt, reserve the same declared resource ceiling and timeout for every arm. Measure selection, reset, dispatch and feedback-update elapsed time and settle it through unchanged PR-05 `Budget`. The same total block ceilings apply; graph/adaptation cannot request extra calls/tokens or change the cap.
3. Record simulated attempts, target-request credits, attacker/target-model credits, retries, tokens and costs separately where explicitly supplied by a fixture. These are labeled test-double values, not actual provider measurements. Actual model IDs/tokens/prices/cost remain null. Absent nonapplicable resource dimensions mean no such simulated resource; explicitly unknown usage is null and closes the ledger. Known receipt usage is preserved even if later feedback validation fails.
4. Preserve failed/unsupported/timeout/reset/unknown/accounting-error slots, candidate-preparation statuses, exact consumed counters and stop reasons. Do not retry/substitute or change caps. Cooperative overruns stop subsequent calls; accounting-only errors never establish a security outcome.

Equal budgets mean identical opportunity/ceiling/stop contracts, not identical realized choices or consumption. Early errors/exhaustion can leave one arm with fewer completed slots and this is recorded. Shared-input accounting isolates information access; it is **not an end-to-end physical graph-construction cost comparison**. An operational study must approve overhead allocation, discovery/profiling request costs, model/token/currency treatment, latency limits and any cost-sensitivity analysis. No price is inferred from keys or model names.

Timeouts are cooperative synchronous checks, not hard termination of arbitrary code. Recorder/fsync/coordinator administration is outside the measured attempt component; that limitation and shared-preparation accounting must be approved or revised before empirical execution. No unbounded external adapter is accepted. Interrupted archives remain incomplete/tamper-checkable, with no usable comparison summary and no automatic continuation/reissue; source PR-05 recovery is not silently applied to a different archive schema.

## Execution, recording and replay

`execute(plan, new_archive, script=None)` records unavailable delivery for every planned slot by default. Passing an exact `Script` permits in-process **data-only** scheduler verification. No callable target/provider adapter is accepted. A script returns no observations, audit evidence, policy decision or oracle verdict, and cannot set a real confirmed outcome. All cells retain security_outcome UNKNOWN, primary eligibility false and actual task success null.

The PR-05 `Recorder` stores a versioned plan/provenance/schedule/script manifest, shared preparation, arm views/initial state, pre-call reservation intents, each cell/reset/response/update/budget, final state and complete denominator summary. Canonical content addresses, hash chains, exclusive append, fsync and an externally retained seal establish consistency, not signatures or authenticated source custody. Recomputed whole archives cannot be independently authenticated by their own hashes.

Offline replay verifies seals, exact fixed schedule/arms, matched graph-free/common inputs and permitted topology, state ownership, choice/update determinism, reset scopes/generations, identical reservation ceilings, measured/unknown accounting, failed/timeout/error disposition and all planned cells. It rejects labels/extra graph data, changed budgets, withheld opportunities, cross-arm state and fabricated security results even when a deliberately inconsistent archive is rehashed in a test.

Passive CLI:

```sh
python -m talos.ablation plan /path/to/design.json
python -m talos.ablation replay /path/to/archive --expected-seal HASH
```

There is no live-execution command. Planning manifests are reproducible for identical inputs/provenance/seeds; real timing is variable and explicitly recorded. Injected clocks are marked synthetic. Deterministic test clocks allow byte-identical test traces; replay uses recorded measurements rather than inventing repeat timings.

## Outcomes, utility and remediation

`observer.recorded_outcome` privately verifies a selected PR-05 archive/action and uses unchanged PR-01/05 replay to preserve its full verdict. Even a fixture CONFIRMED verdict gets independent_reference_status=PENDING, primary eligibility false and primary_count=null. It is never adaptive feedback. No primary result is inferred from a receipt or direct synthetic tool invocation.

`utility_control` checks a supplied nonempty benign response goal against actual replayed PR-05 allowed-action/evidence packets. It distinguishes successful authorized responses, trusted tool failures and missing evidence. Its output is labeled synthetic control only, not general utility. Unit tests use authorized PR-03 helpdesk/document actions in vulnerable/hardened variants; these are separate infrastructure controls, not corpus delivery or attack-arm performance results.

`matched_hardening` verifies prospective PR-03 variant pairs retain the same public inventory/content, scenario/group/reset and actual benign-control content. It rejects changed opportunity/control sets or identical variants masquerading as a comparison. It returns PLANNING_ONLY and no effectiveness estimate.

`legacy_wrapper_control` records the source hash of the existing customer-service `PolicyEnforcingBrain`, its prewritten origin and missing portable adapter. It does not import/run that brain, rewrite legacy policy, invent generated fixes or treat helpdesk/document hardening as the same remediation. A fair legacy wrapper study still needs the same underlying brain/model/task/opportunity/reset/budget controls and authorized-task failures; portable comparison remains BLOCKED.

## Prospective analysis and gates

The versioned contract records A2−A1 (graph at static), A3−A1 (adaptation without graph), A4−A2 (adaptation with graph) and `(A4−A3)−(A2−A1)` interaction. The intended endpoint is independently adjudicated unique unauthorized committed effects/root causes at an approved common target-interaction budget. Case strings, repeats, attempted calls and fixture receipts are not independent discoveries.

No U counts, effect sizes, inferential test or automatic clustering are calculated. Primary counts/effects remain null. Matched planned blocks/selection/utility slots and preparation cells have separate denominators; missing/UNKNOWN/unresolved cells remain visible. Scenario/target and case/root-cause clustering, primary budget, adjudication, uncertainty/interval method and sampling need explicit approved references. Filling references cannot unlock this engineering-only executor.

Operational GO requires reviewed delivery/reset/cancellation, authentic policy/source custody, genuine independent PR-06 labels and root-cause adjudication, valid targets/cohort, allowed feedback/information, budgets/overhead/currency, remediation applicability, environment freeze and approved statistical protocol. No approvals or reviewers are fabricated. Engineering CI is not evidence that graph/adaptation improves discovery or that hardening preserves utility generally. PR-08 is not started.
