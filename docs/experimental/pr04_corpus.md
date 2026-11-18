# PR-04 portable corpus engineering

`Talos-Portable-1.0`, schema `talos.attack-case.v1`, is a passive, repository-authored synthetic dataset. It does not replace or relabel Talos-35. Its 12 cases and 24 bindings are development artifacts, not 12 independent vulnerabilities, human labels or experimental observations. All remain UNASSIGNED and unreviewed. Two domains do not establish generalization.

## Contracts and files

`talos/talos/corpus/` is opt-in; legacy scanner, attacks, score calculations, learning and historical outputs do not import it.

| File | Purpose |
|---|---|
| `models.py` | Frozen, extra-field-forbidden versioned case, provenance, expectation, corpus and content-identity models |
| `taxonomy.py` | Versioned primary-source registry and exact/conceptual mapping validation |
| `planning.py` | Passive role compatibility, fixture bindings, public common pool and restricted graph projection |
| `splits.py` | Complete proposed split coverage and conservative structural leakage diagnostics |
| `loading.py` | Offline package loading with corpus/case/taxonomy manifest verification |
| `data/cases.json` | Explicit synthetic text, roles, prerequisites, boundaries, evidence contracts and provenance |
| `data/bindings.json` | Separate helpdesk/document bindings and proposed actor/argument packets; no invocation |
| `data/taxonomy.json` | Source locators, edition IDs, retrieval limitations and coverage exclusions |
| `data/split.json` | All UNASSIGNED; researcher approval pending |
| `data/manifest.json` | Canonical corpus/taxonomy/binding/split hashes and exact case hash index |

Each case has a unique ID, positive integer revision, family/template/paraphrase groups, parent and scenario ancestry, entry surface, objective, intended policy boundary, prerequisites, semantic tool requirements, public placeholders, stimuli, expected observable evidence, conditional expectations, taxonomy relations and provenance. Tool requirements use PR-02 `Effect` roles. No portable implementation imports customer-service fixtures or infers roles from tool names.

`case_id@revision#sha256` identifies the full canonical case content, including metadata. Serialization is sorted-key UTF-8 JSON with compact separators and finite values. `CaseRecord` verifies its digest; `Corpus` rejects duplicate IDs, missing parents and ancestry cycles. `validate_identity_continuity` rejects content changes at the same ID/revision and revision rollback. A new revision requires a new hash and updated bindings. Parent IDs resolve against the exact corpus manifest. Content hashes do not authenticate authors, verify review, establish independence or prove an exploit. New corpus editions require an explicit schema/version change, not an ignored mismatch.

## Case coverage and conditional expectations

| Cases | Intended engineering coverage |
|---|---|
| DIRECT, DIRECT-PARAPHRASE | Direct instruction override; declared derivative lineage |
| TOOL-DATA, DOCUMENT-DATA | Indirect data-to-instruction trust boundary |
| AUTH-SPOOF | Claimed identity/authority versus actual operator policy |
| TOOL-EFFECT | Unauthorized state-changing action request |
| WORKFLOW | Multi-step lookup-to-action authority confusion |
| DISCLOSURE | Restricted material or communication audience boundary |
| QUOTED | Inert quoted instructions, no tool action requested |
| AUTHORIZED | Legitimate actor/task control |
| BLOCKED | Denied operation with trusted no-effect evidence |
| NO-EVIDENCE | Expected UNKNOWN when required trusted terminal evidence is absent |

These are proposed coverage intentions, not executed attack findings. Cases contain no `observed_outcome` or risk score. Attack expectations admit all five unchanged PR-01 outcomes; controls describe conditional expected behavior, not independent ground truth. A negative control can fail under a later evaluation; expected NO_VIOLATION does not suppress a real adverse observation. BLOCKED requires complete trusted no-effect evidence. Missing or contradictory evidence remains UNKNOWN. A model's claim or tool response cannot establish a confirmed unauthorized effect.

Actual future packets must bind target, actor, authorization context, scenario, run, repeat, action and argument digest; policy denial plus relevant trusted committed state/audit proof, successful reset and finality are required by the unchanged oracle. The corpus records required evidence descriptions and proposed fixture actions, not trusted evidence or authorization grants. PR-01 `Outcome` is reused directly; no new numeric metric or oracle behavior is introduced.

## Passive domain binding and applicability

Bindings isolate concrete PR-03 names, actors and argument packets from portable case templates. Helpdesk primarily proposes entitlement changes and a fixed synthetic manager inbox; document management proposes editor/reader ACL changes. WORKFLOW binds a directory lookup or document search first. Authorized bindings propose manager-to-employee wiki grants or owner-to-manager guide editing; adverse bindings propose denied root access or restricted document changes. Regression tests validate proposed arguments against the actual PR-03 Pydantic tool schemas without constructing environments or executing actions.

`plan_case` takes an exact record, profile and binding. The profile is revalidated/copied. It checks exact placeholders/slots, domain, selected tool existence, role declarations, permission/trust completeness, untrusted-output requirements and action-bound audit/state capability metadata where requested. Known mismatch is INAPPLICABLE. Unknown or conflicting metadata, missing evidence capabilities or unavailable surfaces produce UNKNOWN. A known mismatch can coexist with unresolved details; reasons remain explicit. APPLICABLE means **declared profile compatibility only**, not authorization, safe execution, completed injection delivery or trusted verdict evidence.

The available-surface contract defaults to empty. PR-03 supplies deterministic tools/stores, **not an LLM prompt or tool-output/document poisoning adapter**. Therefore every shipped binding remains UNKNOWN under defaults. Unit tests explicitly declare proposed surfaces to check rendering and portability only. Indirect surfaces are delivery requirements, not claims that a particular PR-03 tool can be poisoned. Tools marked as emitting untrusted content can be required through `needs_untrusted_output`; no trust is inferred from tool names.

The planner does not validate arbitrary unfamiliar JSON Schema dialects or execute prerequisites. Fixture arguments are schema-checked offline in tests; future adapters must validate their schema and exact actor/context/variant/reset permissions. Metadata declarations never grant those permissions. Inapplicable and UNKNOWN preparation cells must not become implicit NO_VIOLATION or silently disappear from a future denominator.

Minimal passive use (no invocation):

```python
from talos.corpus import load_corpus, load_bindings, load_split, load_taxonomy

corpus = load_corpus()
bindings = load_bindings()
split = load_split()  # all UNASSIGNED
registry = load_taxonomy()
```

`plan_case(record, profile, binding)` is UNKNOWN without an explicit surface contract. No corpus loader imports targets, network/model clients, the legacy scanner or global learning. JSON package resources ship through additive `MANIFEST.in`; no dependency changes are needed.

## Public information and future equal-opportunity arms

Private observer records include case identity, groups, provenance, policy assumptions, proposed actor/arguments, evidence requirements, taxonomy and expected outcomes. `public_opportunity` projects only an opaque opportunity hash, full shared public tool inventory (names/descriptions/input/output schemas) and rendered surface/text. Slot-to-tool selection and proposed argument packets are not separately exposed; the intended action remains visible in the payload itself. Public task text is never an authenticated actor identity.

The projection recomputes compatibility rather than accepting forged prepared text. `CommonPool` rejects duplicate opportunity identities. `arm_inputs` gives both future arms exactly the same pool digest and opportunities, with topology in a separate field. Graph data never changes case eligibility or rendered stimuli. `project_possible_graph` projects only PR-02 possible invocation/data-flow topology; it excludes observed paths, scope, action/event identifiers, policy and audit labels. Typed graph input rejects unknown fields, observed relations and nodes outside the common inventory. Possible edges remain possibilities, never observed dependencies or committed effects.

This interface is a PR-07 input contract, **not a runner**. It does not implement arm selection, adaptation, feedback, budgets, network restrictions, reset orchestration or outcome measurement. Observer files must not be made available to an attacker process. Full public inventory/schema access, topology derivation and synthetic fixture visibility are proposed information choices requiring approval. Public fixture source can invalidate an independent TEST claim even if structural split checks pass. A frozen common pool needs reviewed filtering and identical target/budget/feedback/variant opportunities before comparison.

## Split and leakage controls

`SplitManifest` is corpus-hash bound, requires complete case coverage, accepts UNASSIGNED/DEV/TEST and never represents researcher approval. All bindings require exact corpus/case identities, every case requires target-binding context, and every binding requires a complete supplied profile. No shipped case is selected as independently held out.

`check_leakage` compares every proposed DEV/TEST pair on declared family, template, paraphrase group, normalized/near-identical payload text, transitive case ancestry, case/binding scenario ancestry, actual target ID, declared target/fixture family and tool-schema structure. Unicode normalization, case folding and punctuation removal catch superficial text changes; SequenceMatcher's configurable default 0.85 is an engineering flag threshold, not a semantic validation statistic.

Schema signatures remove cosmetic titles/descriptions/examples and rename property/definition identifiers while preserving structural constraints and required membership. They conservatively collapse references and can overflag common primitive structures. Schema comparison includes all described tools, not just selected ones, to catch shared target inventories. Conflicting or unfamiliar schemas are not certified equivalent. Researchers must review false positives, related unseen paraphrases, undeclared shared ancestry and semantics that structural checks cannot detect. Supplying false metadata is not prevented by hashing.

Overlap issues identify both cases and the axis; they block any proposed freeze pending resolution. Even zero issues always reports semantic review required, independent validity not established, and approved_for_evaluation=false. All-UNASSIGNED has no cross-split comparisons and is explicitly unapproved, not a leakage-free TEST cohort. No paraphrase model, clustering experiment or human labels were generated.

## Source-verified taxonomy

Canonical categories and source notes are in `data/taxonomy.json`. Mappings are narrow and version-specific:

- [OWASP's official 2026 LLM download](https://genai.owasp.org/download/56857/?tmstv=1785822482): printed p10 verifies LLM01; p23 verifies LLM03. The publisher's Appendix A pp59–60 verifies ASI01/02/03 relationships. The standalone Agentic PDF could not be retrieved; no claim of inspecting that document is made. The downloaded source contains publication-date placeholders; edition 2026 is recorded without inventing a finalized publication date. Its mutable download URL is a source-custody limitation.
- [MITRE's pinned canonical ATLAS YAML](https://raw.githubusercontent.com/mitre-atlas/atlas-data/f56c1468731d6428e5bf875263b4643b46d67437/dist/v6/ATLAS-2026.10.yaml): content 2026.10, format 6.1.0. Keys AML.T0051.000/.001 verify direct/indirect channel mechanisms; AML.T0053 supplies the related tool-action category. The commit is pinned; deprecated v5.6.0 is not used.

Only direct/indirect mechanism mappings to corresponding channel categories are `exact_mechanism`. LLM03, ASI and tool-action relationships are `conceptual`: shared risk dimensions do not establish case equivalence, vulnerability validity or exhaustive framework coverage. Controls carry no attack mappings. Registry validation rejects unknown editions/categories, mismatched attribution, duplicate mappings and unsupported exact relations.

No memory poisoning, supply-chain, arbitrary-code or multi-agent protocol coverage is claimed. Labels and narrow locators are attributed; external case texts or empirical findings were not imported. Source license references remain upstream; repository asset release/licensing requires researcher decision.

## Provenance

All text and fixture bindings were explicitly authored during PR-04 as deterministic repository synthetic fixtures, without model generation or target execution. DIRECT-PARAPHRASE is a declared derivative of DIRECT. Source references link the new specification and PR-03 fixture implementations; taxonomy sources describe classification only and are not the origin of these attack texts. No independent supplier or human reviewer is claimed. `independently_supplied` is a supported provenance declaration for future cases, not a validity switch; independent_validity remains not_established. A supplied review reference records a reference only.

Source JSON is the reproducible authored artifact. Loaders validate and round-trip it offline; the manifest freezes canonical content. Original documents, Talos-35, prior tests/source and raw results remain unchanged. Historical custody and original user-file fingerprints are checked separately in the GO/NO-GO report.

## Researcher decisions still required

1. Case applicability: delivery adapters, prerequisite verification, target variants, authorized actor/task context, included/excluded cells and treatment of UNKNOWN preparation.
2. Primary units and denominators: unique confirmed root causes versus cases/templates/repeats; how controls, inapplicability, failed delivery, missing evidence and correlated repeats enter accounting. No numeric v2 score is defined.
3. Family clustering: independent scenario/root-cause review, ancestry truth, cross-domain/schema overlap policy and permissible split reuse. The groups here are proposed metadata, not independent root-cause labels.
4. Attacker information: shared inventory/schema visibility, topology derivation, observed feedback, private source access, allowed mutations and adaptive/static budgets. The common pool alone does not prove a fair experiment.
5. Custody and approvals: reviewed target ownership/policy/evidence trust, independent cases and two-rater labels, source-license/release decision and a signed freeze/held-out manifest.

These do not block passive engineering review. They block operational or independent-evaluation claims. PR-05 and later execution require a separate request and review gate.
