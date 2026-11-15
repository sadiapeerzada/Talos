# PR-02: Portable target profiles and graph classification

Base: `2ab0d711259eb94ad3807c6eaebeb776cc7e1843`, latest remote main when this branch was created. PR-01 #15 was confirmed merged through GitHub metadata and local ancestry. Branch: `research/pr-02-portable-profiles`; isolated worktree: `/private/tmp/talos-pr02`. The [decision ledger](pr02_engineering_decisions.md) records unresolved custody, authorization, trust and research gates. No researcher approvals are invented.

## Scope and compatibility

This is an opt-in offline profile/graph layer. **Every pre-existing tracked file remains byte-identical**, including legacy graph discovery/classification, the scanner, all scoring/risk behavior, PR-01 oracle/capture, existing tests, historical JSON/reports, README and manuscript-related artifacts. Original uncommitted policy/adapter/report changes and the untracked backup remain in the original checkout, excluded from this PR.

New code lives in `talos.profiles` and `talos.graph.portable`. It consumes supplied inventories, JSON profiles and previously captured trace sequences. It never discovers a network endpoint, invokes a model, executes tools, resets target state, runs attacks or selects a study budget. No new third-party dependency is introduced. Legacy callers still use the legacy API and behavior; portability is available explicitly through the new profile path.

| Surface | Version |
|---|---|
| Target profile | `talos.target-profile.v2.0` |
| Semantic classifier | `talos.profile-classifier.v2.0` |
| Portable graph | `talos.profile-graph.v2.0` |
| Supplied execution-path schema | `talos.execution-path.v2.0` |
| Compatible oracle | PR-01 `talos.action-oracle.v2.0` (unchanged) |

## Profile contents and provenance

`TargetProfile` describes:

- Target/domain/fixture identity and a **custody declaration**, whose optional independence claim requires provenance but is never verified by this code.
- Available tools, descriptions, input/output schema objects, parameter types/required lists/nested structures within those schemas, effect claims, permission/boundary claims, output-trust claims and audit/state capability references.
- Authorization boundaries with descriptions and optional policy ID/version/rule identity. Missing policy identity is an unresolved boundary, not an inferred permission.
- Audit, state-transition and reset capabilities, declared ability to observe commitment/no-effect and bind action digests, source IDs and supporting evidence. These are capability descriptions, **not trusted-source configuration or functioning adapters**.
- Possible flow declarations with provenance; reset description, intended test objectives, prohibited effects, declared egress and privacy references. Text in these fields does not authorize execution.
- Metadata evidence IDs, source IDs, references, origin (`operator_declaration`, `target_declaration`, `documentation`) and human-reviewable details.

All semantic claims reference explicit metadata evidence. Duplicate tool/evidence/boundary/capability/flow IDs and dangling references are rejected. Unknown schema versions/enum values and extra fields fail validation; inputs must contain finite JSON data. Profiles can intentionally leave semantics missing, with classifier abstention instead of invented values.

Input/output schemas are preserved, including unfamiliar nested arrays, unions and references. This package does **not** implement a full JSON Schema validator, resolve `$ref`, fetch remote schemas, infer policy from parameter names, or prove that a declaration describes real behavior. The positive text-shape detector only recognizes explicit string-bearing schema structure; a missing candidate edge under incomplete/ref-only schemas is not evidence that no flow is possible.

The profile SHA-256 fingerprints its canonical JSON representation; it is not a signature, approval or authentication. Frozen model fields do not make nested dictionaries a tamper-proof archive. Classification, graph construction and policy binding revalidate/copy caller profiles before using them. Input trace observations also retain the PR-01 action digests that bind target/scenario/run/repeat/action/actor/authorization context/tool/arguments.

## Conservative classification

Classification uses explicit effect/permission/trust declarations and their provenance. Tool names and natural-language descriptions supply **no default authority or effect category**. A renamed `opaque_17` with equivalent metadata is classified identically; a tool named `lookup_safe_readonly` with no semantics remains unknown.

| Declared effect | Derived side-effect class / role |
|---|---|
| `read_only` | read-only (a declared absence of state/external effects, not a safety verdict) |
| `state_changing` | state-changing |
| `external_communication` | external communication |
| `financial_write` | state-changing + financial-write role |
| `external_send` | external communication + external-send role |
| `privileged_write` | state-changing + privileged-write role |
| `read_untrusted`, `sensitive_read` | corresponding role; do not alone establish read-only behavior or permission |
| Missing/explicitly unknown effects | unknown side effects |

State-changing and externally communicating effects may coexist. An explicit read-only declaration conflicts with a state/external declaration and yields unknown side effects with a conflict reason. Permission is independent of effect: known financial/write effects do not fabricate a privilege contract, and an explicitly read-only tool with unknown permission is not declared safe.

Permissions are `public`, `authenticated`, `privileged` or `unknown`. Any non-unknown classification requires a referenced complete versioned authorization boundary. Missing permissions, incomplete boundaries and conflicting permission declarations yield unknown; there is no low/public/read-only fallback. Public is still a declaration, not an ALLOWED oracle decision. Conflicting output-trust claims yield unknown rather than choosing the most permissive source. Each classification reports status (`declared`, `incomplete`, `conflicted`), supporting evidence IDs and reasons. **Declared is not verified.** There is no invented confidence score.

`profile_from_tools()` converts an already supplied list of generic `ToolSpec` objects, preserving parameter metadata while leaving effects, permissions, output schema and trust unresolved. It performs no tool discovery call. This supports existing inventory formats without importing customer-service fixture data or inheriting the legacy keyword classifier's safe defaults.

## Graph relationships and evidence

`build_profile_graph()` returns a NetworkX `MultiDiGraph` with typed node namespaces (`input:user`, `tool:<name>`), version tags, profile digest, source metadata and classifications. Parallel edges retain independent support without upgrading possible paths into observed facts.

| Edge relation | Supporting evidence | What it does not prove |
|---|---|---|
| `possible_invocation` | declared exposed tool + tool evidence IDs | executable reachability, policy authorization or actual invocation |
| `possible_data_flow` from a profile flow | flow description and evidence IDs | observed transfer or exploitability |
| `possible_data_flow` schema candidate | string-bearing source output and destination input; source trust untrusted/mixed/unknown; destination effects state/external/unknown; both tools' evidence IDs | actual compatible value transfer, runtime dependency, authorization or malicious impact |
| `observed_call_order` | supplied trace path source/reference, scope, action digests, sequence positions and event IDs | authenticated chronology, data dependency, committed impact or a policy violation |

Schema candidates are intentionally bounded tool-level hypotheses, not an exhaustive graph: they omit same-tool candidates and unsupported/ref-only text shapes. Explicit profile flows and recorded sequences can represent self-relationships. No missing edge constitutes a clean bill of health. Declared trusted output can suppress a schema candidate, so metadata integrity and researcher review remain essential; this is never treated as evidence of actual trusted output.

Observed paths must share target/scenario/run/repeat, have unique action/event/sequence identities, match event action digests and use tools present in the profile. Sequence positions, not tuple insertion order or guessed timestamps, determine order. Accepted/executed statuses in supplied traces can support call order only. Request-only, blocked, absent or ambiguous execution records and sequence gaps omit observed edges, with diagnostics; they are not bridged into a fabricated adjacent path. No observation converts a schema candidate into proven data flow. COMMITTED text in a supplied trace does not bypass the PR-01 audit/state oracle.

`graph_json()` preserves every relation, rationale, reference and metadata pointer in deterministic JSON. A normalized SHA-256 binds each supplied execution path's content, including event statuses; it does not authenticate it. Full supplied profiles/paths must be retained alongside exported graphs for replay. The graph is not a signed immutable recorder; that remains later work.

## PR-01 oracle boundary

`ProfileBoundPolicy(profile, delegate=None)` implements the PR-01 policy interface. Without a separately supplied policy it returns UNKNOWN. A target/tool mismatch, missing/conflicting permissions, mismatched action digest or policy ID/version/rule outside the tool's declared boundary also returns UNKNOWN. Only the explicit delegate may assess actual authorization. The delegate must validate arguments, resource ownership, consent and policy semantics; the wrapper is not a JSON Schema argument validator.

Profiles do **not** create an evidence reader or populate `trusted_source_ids`. Even a profile advertising an audit receipt and action-digest capability cannot produce CONFIRMED unless the caller separately supplies a reviewed evidence reader and trusted-source configuration, and PR-01's commit-witness checks pass. The tests demonstrate that a profile-listed source with no explicit oracle allowlist still yields UNKNOWN.

## Offline use

```python
from pathlib import Path
from talos.profiles import TargetProfile, classify_profile
from talos.graph.portable import build_profile_graph, graph_json

profile = TargetProfile.model_validate_json(Path("target-profile.json").read_text())
classifications = classify_profile(profile)
graph = build_profile_graph(profile)  # no target contact
serialized = graph_json(graph)
```

A machine-readable schema is generated directly from the model, without network access:

```sh
python -c 'import json; from talos.profiles import TargetProfile; print(json.dumps(TargetProfile.model_json_schema(), indent=2))'
```

No new execution CLI is introduced. The new APIs deliberately do not change the default scanner pipeline or authorize PR-03 targets/studies.

## Synthetic controls and limits

`talos/tests/fixtures/portable_profiles.json` is labeled `test_only` and `not_empirical`. It contains two dissimilar synthetic schema families (document/share and operations/payment/notification) plus incomplete/conflicting descriptors. The profiles are declarations authored for unit controls, not independent target implementations, real deployments or evaluation findings. Their custodian independence is not established.

Fixture SHA-256: `c454a97bcab773a7bfd35ff0b0ee07c0c7a8c70ae977b8f33c2686a47a2b3687`.

Quality checks use explicit toy expectations: all 10 fixture tools' permission/effect/role outputs match their expected declarations, including 3 unknown permissions in the ambiguous fixture; the two complete families' 4 expected schema-candidate tool pairs are present with zero extra pairs. Renamed tools/parameters preserve the same mapped relationships. These are deterministic test assertions, **not measured population accuracy, independent validation, a held-out empirical split or evidence of graph-aware efficacy**.

Further controls cover unknown inventories, nested/ref-only schemas, metadata conflicts, missing versioned boundaries, invalid references/versions, duplicates, profile snapshots, graph/path fingerprints, observed-versus-possible edges, scope mismatches, blocked/request-only steps, sequence gaps, oracle compatibility and no fixture imports.

## Research stopping boundary

**BLOCKED:** independently controlled target custody, verified metadata/schema truth, authorization contracts, source authentication/finality and trust review, independent labels, numeric v2 risk semantics and experiment approval. No profile or test result closes these decisions.

For eventual equal-budget comparisons, freeze the same target/profile version, metadata provenance, policy/oracle, scenario/reset state and opportunities for all arms. Retain profile/graph/path digests and do not let adjudicated labels or held-out outcomes drive graph construction. The graph-aware arm may use derived graph features while graph-blind controls retain their prespecified information/budget; common oracle/trust contracts must not vary by arm. Request/cost scheduling, data splits and efficacy experiments remain later protocol work. Building this graph makes no target interaction and supplies no current efficacy estimate.

Stop after PR-02 for review. No new targets, inference, attack evaluation, external scan, historical rewrite, manuscript edit or PR-03 implementation is included.

## Validation record (2026-11-15)

**VERIFIED:** final offline suite: **199 passed, 1 warning in 8.48s**. This includes all 153 unchanged legacy/PR-01 tests plus 46 new controls. Warning: existing Starlette/httpx TestClient deprecation. Focused new controls: 46 passed. JSON Schema generation from `TargetProfile.model_json_schema()` also completed offline. No dependencies were installed or upgraded.

Exact final command, cwd `/private/tmp/talos-pr02/talos`:

```sh
env -u ANTHROPIC_API_KEY -u GROQ_API_KEY -u OPENAI_API_KEY -u LANGSMITH_API_KEY -u LANGCHAIN_API_KEY -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY LANGSMITH_TRACING=false PYTHONPATH=/private/tmp/talos-pr02-support:/private/tmp/talos-pr02/talos /Users/sadiapeerzada/Talos/talos/.venv/bin/python -m pytest tests/ -v > /private/tmp/talos-pr02-final.log 2>&1
```

Temporary test-only support follows PR-00/01's isolation pattern: redirect storage to `/private/tmp/talos-pr02-state` and block non-loopback socket connections; remove model keys/proxy settings. Local loopback permission supports existing fixture integration tests. No classification, scoring, oracle, assertion or target behavior is patched. This temporary support is not a product sandbox. New controls use only supplied/canned in-memory data; no new empirical attack evaluation or standalone scan was launched. Opening the PR may trigger the repository's existing CI fixture workflow.

**VERIFIED custody:** all **95 pre-existing tracked paths** retain their base SHA-256, including every historical artifact, original test and all PR-00/01 code/documents. All four original modified/untracked user-file fingerprints also remain unchanged. The change is additions only. Document links resolve and `git diff --check` passes.

Local environment: Darwin arm64, Python 3.13.7, pytest 9.1.1, reused existing virtualenv. **PENDING:** hosted Python 3.11/3.12 CI at submission; no minimum-version or historical-environment certification is asserted. Full local transcript is retained at the command's output path. Remaining research gates are recorded in the decision ledger and the research stopping boundary above.
