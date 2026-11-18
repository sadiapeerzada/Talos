# PR-05 reproducible offline execution infrastructure

This is an opt-in engineering harness for researcher-controlled synthetic fixtures. It is not a main campaign, prompt-injection delivery system, independently reviewed oracle or permission to conduct a study. Talos-35, historical reports/results, legacy CLI/dashboard/scorer and numeric risk definitions are unchanged. The supplied final experimental plan v1.0 and merged PR-00–04 govern this phase.

## Interfaces and recorded identity

`talos.research` adds separately versioned run, event and seal contracts. `RunPlan` records source commit, dirty flag and full source-tree content fingerprint; actual Python/platform/dependency versions and dependency-lock hash; exact corpus content, profile snapshot/version, target fixture version, policy ID/version and PR-01 oracle version; scenario/case/binding/run/repeat identities; seeds, ordering, timeouts, budget ceilings, learning snapshot and optional explicit operator trust declaration. Frozen binding packets supply the proposed actor and exact arguments. Reset receipts bind generation and authorization context; observations bind each action ID/digest.

`capture_provenance` reads actual Git and package metadata, never API keys or environment secrets. Model identities are null because no model adapter is implemented. Runtime dependency inventory is recorded even when the environment differs from the proposed lock; a lock hash alone is not proof of an approved or matching study environment. Dirty source is explicitly fingerprinted, not presented as a clean frozen commit.

`CellResult` preserves the complete PR-01 `Verdict` when available, including policy and evidence references and uncertainty. Without a valid action/packet the cell is UNKNOWN with a separate abstention reason, not a fabricated action or verdict. Unsupported delivery, inapplicability, reset failures, timeout, interruption, missing cells and budget exhaustion have distinct states. All planned cells remain in accounting; controls, attempts and workflow steps are not independent root causes.

`Packet` stores full observation, measured request latency, policy assessment, whether it was enabled for adjudication, complete normalized evidence and reader issues, raw operator action/audit/snapshots, reset receipt, exact source selection and full oracle verdict. Missing tokens/costs remain null, not zero or estimated. Cell elapsed time includes controller work; request latency measures the synchronous tool request. Structured error types/modules/stack locations are recorded; exception values and source-line text are suppressed to avoid secret/PII leakage. These public synthetic fixtures must not contain real secrets or personal data.

## Delivery and authorization gates

Two cell modes have deliberately different meanings:

- `corpus_delivery` (default): use PR-04 identity/applicability planning, then record UNKNOWN/delivery_unavailable. PR-03 has no reviewed agent prompt, tool-output poisoning or document-delivery adapter. There is no model call or tool invocation in this mode.
- `direct_fixture_control`: explicitly invoke proposed PR-03 tool operations to test infrastructure. This is a local tool/state regression, never a delivered or successful prompt-injection case. The manifest labels this distinction, and every per-cell intent records the mode.

`DeliveryAdapter` defines adapter identity/version, supported surfaces, public opportunity input and deadline. `UnavailableDelivery` has no supported surfaces and cannot deliver. No custom adapter is accepted by the executor in this phase. Existing PR-04 common-pool interfaces remain the shared opportunity source for later comparisons; PR-05 neither selects DEV/TEST nor implements arms/adaptation/feedback/randomized comparative schedules.

An absent `TrustDeclaration` cannot confirm effects. With an explicitly supplied synthetic-regression declaration, the executor checks the exact environment source and versioned policy, records the actual policy assessment and uses the unchanged PR-01 oracle. The declaration is operator-supplied reference metadata, **not authenticated human approval**. Regression tests provide labeled test-only references; no shipped operational study approval or default source allowlist exists. The runner cannot prove real-world ownership, reviewer independence or trust. Operational policies/sources still require researcher/custodian review outside this fixture harness.

Only the exact local `ControlledEnvironment` class is supported. Its target/profile and fixture/policy versions must match the manifest. There is no arbitrary target client or network model adapter. Metadata and task text never grant actor permission.

## Determinism, isolation and timeouts

The declared cell order is retained or shuffled through a fresh local `random.Random(seed)`. Global random state, SQLite learning/history, API keys and provider availability are not read. Learning is either disabled/empty or an explicit finite supplied snapshot whose content hash is frozen in the manifest. The snapshot is recorded only; this phase does not apply learned reordering or train anything.

Every executed cell resets the synthetic store with exact scenario/run/repeat scope. Healthy reset receipt, actual state digest and deterministic seeded business state are checked before a call. Failed/incomplete resets yield UNKNOWN and zero tool calls. Existing PR-03 reader context/lineage/finality checks remain intact. Fresh reset generations prevent prior repetitions or runs from influencing business state, including when an operator reuses an environment instance. State stores are isolated temporary PR-03 stores; their full relevant action/state evidence is archived before closure. They are not production endpoints.

Timeouts are cooperative for these bounded synchronous SQLite fixtures: check before each workflow action, record measured latency, and mark late evidence incomplete before judging. An injected PR-03 timeout remains UNKNOWN and stops later cells. An elapsed reservation overrun stops future calls and marks the cell non-confirming; already captured action-level verdicts remain separately preserved, not silently erased. Archive/control overhead contributes to the cell's elapsed budget. This is **not forcible cancellation** of an arbitrary blocking tool. No unbounded provider/HTTP adapter is implemented; hard process isolation/cancellation is a required later gate.

No hidden retries, substitutions, target/model fallbacks or budget changes occur. Durable intent precedes any reset/tool side effect. Exceptions preserve cells and charge calls that were requested, including tool exceptions. Process interruption after intent can leave call/usage uncertainty; recovery never guesses that nothing happened.

## Budgets and denominators

`Budget` enforces exact nonnegative integer dimensions: attempts, target tool requests, attacker model/generation calls, target model calls, retries, input/output tokens, cost microunits and elapsed milliseconds. Every dimension needs a declared ceiling. Before a fixture-control attempt it reserves one attempt, the full proposed workflow's maximum tool requests and the cell timeout. A reservation cannot be overlapped or oversubscribed. Measured actual use is settled and recorded, including overages. Missing usage closes the ledger, exposes null totals plus known lower bounds and missing dimensions, and prohibits further calls.

The present tool-only path has zero attacker/model calls or retries. Token/cost measurements and model IDs remain null/not applicable. No currency or provider price is assumed. A future cost-bearing adapter must declare units/currency and pre-reserve a defensible ceiling; this phase supplies accounting interfaces, not a cost estimator. Request budgets count tool invocation requests (including failed requests), not reset/controller storage operations. Preparation-only delivery blockers use no attempt/tool-call budget and remain counted as UNKNOWN preparation cells.

Summary accounting retains planned and recorded cell counts, missing cell IDs, exact five-way outcome counts, cell-state counts, execution-intent count, action count and exact per-action outcome counts. Workflow actions and cells are separate units. It does not choose a scientific denominator, root-cause clustering, weighting, risk score or inference about efficacy. A preflight workflow reservation can conservatively refuse a case even when a partial workflow could fit; it never substitutes a cheaper case. Later equal-budget scheduling requires researcher decisions and shared ceilings/opportunities across arms.

## Append-only archive and replay

Archive layout:

```text
run-directory/                  # new directory, never overwrite existing output
  .writer-lock                  # exclusive OS advisory writer lock
  objects/<sha256>.json         # canonical content-addressed payloads
  events/00000000.json ...       # ordered sequence, previous event hash, payload hash
  seal.json                     # event count + final chain head
```

Canonical JSON uses sorted keys, compact separators, finite values and deterministic UTF-8 bytes. Full payload files are fsynced then exclusively hard-linked into place, followed by directory fsync. Existing files are never replaced. Events reference payload hashes and previous event hashes. Terminal sealing prevents ordinary reopen/append. Atomic checkpoints occur per event; a crash may leave unreferenced objects or temporary files, which do not authorize another call.

Manifest payload includes the exact plan/configuration hash, private full PR-04 corpus and binding snapshots, profile-derived PR-02 graph (possible edges, no invented observed path), learning hash, explicit execution order and unavailable adapter identity. Every workflow action is separately archived; final cell packets do not discard intermediate outcomes.

`verify` checks canonical bytes, content addresses, event order/chain and final seal; optional `expected_seal` checks a separately retained content identity. Symlink entries, event gaps, malformed/missing payloads, unsealed completion and changed heads fail. A complete replay additionally checks exact embedded corpus/binding/plan identity, deterministic order, learning hash, no duplicate cells/actions/intents, action/actor/run/repeat/reset/policy/trust scope, raw snapshot hashes/lineage, normalized/raw state consistency and summary denominators. It re-runs the same PR-01 oracle against **captured** policy/evidence, without reconnecting to a target or reading mutable current state. Different oracle behavior fails consistency verification.

Hash chains and fsync are tamper-evident consistency controls under filesystem custody, **not signatures, independent authentication, encryption, anti-rollback storage or protection against an OS owner**. Wholesale replacement/recomputed chains or deletion of an unpinned unsealed tail cannot be independently disproved without an externally retained seal/head. An attacker controlling supplied policy/evidence metadata can forge an internally consistent packet. Independent source custody and validation remain required.

`finalize_interrupted` reads/verifies a partial archive, records unresolved cells as UNKNOWN/interrupted, and seals an accounting-only recovery with usage explicitly unknown. It never reexecutes committed, indeterminate or unstarted cells, and never retries an action. Completed packets remain intact. Continuing execution requires a new explicit plan/run; automatic at-least-once recovery is intentionally unsupported to avoid duplicate side effects. A sealed or already terminal run cannot be resumed.

Passive CLI (existing Talos CLI unchanged):

```sh
python -m talos.research plan /path/to/run-plan.json
python -m talos.research replay /path/to/archive --expected-seal HASH
```

There is no CLI live scan/inference command. The Python fixture-control API requires an explicit plan, environment and new archive path. The code never rewrites historical artifacts.

## Network and inference boundaries

`NetworkPolicy` defaults to no origins/addresses. Proposed destinations require exact normalized scheme/host/port, explicit address pinning, explicit resolved addresses for hostnames, HTTPS for external destinations and no credentials/fragments/encoding ambiguity. Private, link-local/metadata, multicast, unspecified and IPv4-mapped IPv6 addresses are denied; loopback requires explicit synthetic-fixture permission. Redirects and DNS/address changes are rejected. Validation never performs implicit DNS lookup or opens a connection. Even a valid destination cannot be requested: transport is unavailable. This is a conservative contract for future adapters, not approval of an external endpoint.

`InferenceGate` requires explicit opt-in/model/reference, then still rejects because no provider adapter is implemented. Presence of an API key cannot enable inference. These are application interfaces, not a sandbox against malicious arbitrary Python/OS code or monkeypatching. The test/CI socket guard is also not a production egress firewall.

## Reproducibility and CI

`requirements-research.lock` pins transitive project/dev and build dependencies with package hashes and universal Python markers, constrained to existing regression versions. `research-baseline-constraints.txt` records those starting versions; optional external integrations are not installed merely because they appear as constraints. `research-build.in` pins build tools for no-build-isolation project install. The lock was generated with existing uv 0.11.29:

```sh
uv pip compile talos/pyproject.toml talos/research-build.in \
  --constraint talos/research-baseline-constraints.txt --extra dev --universal \
  --python-version 3.11 --generate-hashes --no-header \
  --output-file talos/requirements-research.lock
```

No dependencies in the original user environment were installed/upgraded. Hosted `research-offline` CI installs with `pip --require-hashes`, then installs the project with `--no-deps --no-build-isolation`. Python 3.11/3.12 each run the full offline suite and save test/environment artifacts. Lock resolution/package downloads are reproducibility setup, not inference or target scanning. Python/OS/actions themselves are recorded/selected by CI, not a complete container-image freeze; a signed study environment remains pending.

The explicit `tests/offline_support/sitecustomize.py` is active **only** when its directory is put on PYTHONPATH. It isolates legacy learning/dashboard storage in a fresh declared test directory, blocks non-loopback DNS/connect/connect_ex, and is inherited by local fixture subprocesses. Provider credentials/proxies are removed and tracing disabled in research CI. Production/legacy startup is unchanged.

Outcome-based golden tests require known vulnerable unauthorized effect = CONFIRMED, hardened denial = BLOCKED, legitimate actions = NO_VIOLATION, and missing audit = UNKNOWN. The sentinel runs actual golden tests in a subprocess with test-only detection disabled and asserts a failing pytest exit. This gate fails if positive detection disappears or negative controls incorrectly confirm; no saturated legacy risk score is used as its oracle. The historical score formula, baseline artifact and existing risk-gate workflow are preserved.

## Outstanding approvals and limits

Operational use remains NO-GO pending reviewed target ownership/actor policy/source custody/finality; working reviewed delivery adapters and hard cancellation/containment; approved applicable cells and exclusion/UNKNOWN/denominator semantics; root-cause and family independence; permitted attacker information/feedback and equal budgets; real independent labels, licenses and an approved frozen split/environment. No human approval, external target, trusted operational source, model or DEV/TEST cohort is selected here.

This phase demonstrates offline engineering controls, not attack effectiveness, oracle agreement with independent human labels, real-model security or generalization. PR-06 and the main campaign are not started.
