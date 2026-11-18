# PR-06 oracle-validation infrastructure

**Engineering implementation; independent validation PENDING/NO-GO.** No genuine reviewers, independently supplied labels, approved sampling plan or authenticated reference sources were supplied for this task. No measured oracle accuracy or human agreement figure is reported. Unit-test mathematics and synthetic challenges are not independent validation.

Governing context: finalized experimental master plan v1.0, original roadmap and merged PR-00–05. PR-05 #20 is merged at `60759c9fa03c2beda3a05023132412e48af36471`, the fetched branch base. All prior source/data/behavior remain unchanged. No PR-07, campaign, inference, external scan, held-out selection or publication work is included.

## Versioned artifacts and identity

`talos.validation` is opt-in and has no integration into legacy CLI/dashboard/scoring. It adds:

| Component | Purpose |
|---|---|
| `models.py` / committed JSON Schema | Separate reference facts/category, reviewer declarations, assignments, submissions, adjudications and clearances |
| `packets.py` | Verified PR-05 archive selection and blinded, pseudonymized evidence projection |
| `instructions.py` | Case-neutral versioned guidance frozen with each study |
| `workflow.py` | Coordinator-private append-only study, distinct artifact snapshots, exports/imports and adjudication |
| `metrics.py` | Five-way matrices, explicit denominators, Cohen's kappa and whole-cluster resampling |
| `report.py` | Human-provenance/protocol gates, missing/adjudication accounting, strata and non-certifying report |
| `__main__.py` | Offline schema, export, submission, adjudication, seal and report commands |

`ReferenceLabel` records exact sample/view identity, policy ID/version/rule, authorization, effect disposition, policy violation, evidence completeness/finality/custody, citations, confidence/uncertainty, rationale and explicitly selected category. Submission adds declared authorship, human-versus-synthetic origin, own reviewer pseudonym, timezone-aware review times and blinding-loss disclosure. No field is filled from oracle predictions. Logical checks reject gross fact/category contradictions; these checks do not establish ground truth.

PR-05 oracle predictions retain their original version, complete verdict and action digest. They are never rewritten by reference labels or adjudication. Review packets, instructions, private mappings, predictions, reference submissions and adjudications have distinct versioned content-addressed objects in the private study journal. A manifest pins their identities. Original PR-05 evidence remains separately sealed and unchanged; it is selected by externally supplied seal and exact action ID, never automatically sampled.

Duplicate samples, underlying action digests, assignments and reviewer/sample pairs are rejected. The same underlying action cannot be made independent by a different sample name, key or archive wrapper. Repeats/related cases must retain declared case, target and independence-cluster IDs. These declarations require review; hashes do not establish independent units.

## Blinding and evidence limitations

`from_archive` first verifies and fully replays the selected sealed PR-05 run. It exports an explicit allowlist of raw stored action/status, raw audit events, before/after snapshots and reset record, plus externally supplied policy text/principal/task context and optional source supplements. It does **not** export the oracle verdict, computed authorization assessment, normalized reader completion judgment, reader issues, attack family/arm, fixture variant, generated expected answer or another reviewer's label.

A private key of at least 32 bytes pseudonymizes scope IDs/digests. Original run/scenario/action IDs are absent from reviewer views. Tool arguments, principal identifiers and business-state facts remain available because authorization/effects cannot be assessed without them. Projected content gets its own digest and is explicitly marked transformed, not presented as original raw bytes. The key/linkage stay private; the synthetic test key is not a production privacy key.

Structured prediction/arm/label keys are rejected recursively. **Arbitrary text, business data, policy references, tool names and external documents can still reveal answers or identities.** An exact-view curator clearance must bind both packet and frozen instructions before export; this is a supplied declaration, not automatically authenticated review. The coordinator must inspect all text, links and retained business identifiers before distributing it. If redaction is needed, preserve original evidence and create a reviewed new packet/study version; never silently edit an assigned view.

PR-05's archived raw records do not contain the complete SQLite database/finalization journal. A synthetic tool receipt or two snapshots alone cannot independently establish complete finality/source authenticity. Reviewers must request separately custodied supplements where necessary, or use UNKNOWN. Supplements are also subject to leakage screening and exact-view clearance. A metadata claim of completeness or a hash cannot remedy missing proof. Independent source custody and reviewed policy text must be established outside the attacked target's outputs.

`PolicyMaterial` is supplied by the coordinator/custodian; it is not copied from `FixturePolicy.assess()`. Its review reference is a declaration, not approval invented by the code. Actual policy/actor/task semantics, source provenance, reset assumptions and relevant effect boundaries must be explained to reviewers. A correct-looking fixture behavior is not independent ground truth.

## Offline workflow

See [reviewer procedure](pr06_reviewer_workflow.md). Protocol creation requires two distinct assigned raters and a separate adjudicator, each with externally supplied identity/independence references. No reviewer is chosen or impersonated by the system. The supplied protocol template is deliberately incomplete and cannot be used until actual decisions and assignments are filled.

1. Custodian retains the original sealed source and an independently recorded seal/head. Researcher supplies approved sampling, policy/source material, cluster definitions and protocol/reviewer assignments. No DEV/TEST assignment occurs here.
2. Coordinator calls `from_archive` for each explicitly chosen action. Returns separate reviewer packet, private sample manifest, private prediction and private linkage. Preview is for disclosure inspection, not independent annotation.
3. `Study.create` freezes these artifacts, guidance and assignments in a new private directory. Replacing evidence/predictions after annotation begins is rejected.
4. For each reviewer, export only their own assignment, the common packet, frozen instructions and a **blank** submission template. Both raters get identical evidence/guidance. A later second export does not disclose the first rater's label. Bundles must be outside the private coordinator archive.
5. Humans fill their own files and return them through an approved channel. Import checks exact view/policy/citations, assigned pseudonym, disclosure and timestamps, plus declared authorship/blinding. Labels are captured as immutable snapshots; later editing the original input file does not edit the ledger.
6. Only after both initial submissions may the adjudicator receive both labels, their hashes and fact/category disagreement record. Oracle prediction and arm remain absent. A separate assigned adjudicator documents final evidence-based judgment and rationale, citing both exact original submissions and explicitly recording whether they remained blind to oracle/arm information. Disclosed adjudicator exposure is preserved and excludes that reference comparison. Confidence/rationale differences are retained; differences in core facts or category block automatic consensus. No majority vote is used.
7. Seal the study. Reporting requires the expected study seal, preserves all missing/unresolved cells and never certifies independent validation. Corrections after import require a documented new protocol/study version referencing the original seal, with originals preserved; no overwrite or silent relabel is supported.

The private directory contains predictions/linkage and must never be handed to reviewers. File-based handoff assumes actual OS/account/channel separation by the coordinator. An API caller with the coordinator archive can inspect private records; software cannot prevent collusion or prove two pseudonyms are physically independent people. Assignment/reference declarations and timestamps are not identity authentication or digital signatures. Disclosure timestamps and imported review times must be consistent; resolve real clock errors transparently rather than fabricating times.

## Metrics and denominators

Matrices use reference rows and oracle-prediction columns across all five categories. Every scalar ratio stores numerator, denominator and value; zero denominator means null. UNKNOWN/UNKNOWN matches are visible in five-way accuracy and are not allowed to inflate selective accuracy invisibly.

- Five-way accuracy: equal category pairs / all paired reference actions, including UNKNOWN as a class.
- Reference-known accuracy: equal pairs / actions with non-UNKNOWN reference; oracle abstention counts as a nonmatch.
- Selective accuracy: equal pairs / actions with both reference and prediction non-UNKNOWN.
- Coverage: non-UNKNOWN predictions / paired actions. Oracle and reference UNKNOWN rates have explicit paired-action denominators.
- Per-class precision, recall and false-positive/false-negative rates use the complete nominal five-way one-versus-rest matrix. These are category-error statistics; UNKNOWN references are another category here, not verified negative physical effects.
- Separate confirmed-effect statistics exclude UNKNOWN references. FPR is predicted CONFIRMED among verified non-CONFIRMED references / verified negatives. Miss-or-abstain rate is non-CONFIRMED prediction, including abstention, among verified CONFIRMED references / verified positives. Precision uses only predicted-confirmed actions with a known reference. This conditional precision does not claim unknown-reference predictions are correct; their exclusion count is explicit.
- Operational oracle UNKNOWN rate over all planned prediction artifacts is labeled prediction accounting, not measured validation accuracy. All selected actions require a prediction artifact; absent/mismatched artifacts fail identity validation rather than becoming negative labels.

Two-rater raw agreement/disagreement use both initial labels before adjudication. Cohen's kappa is `(observed agreement - expected agreement) / (1 - expected agreement)` using nominal class marginals. No paired ratings or degenerate single-category marginals yield null kappa with a reason. Agreement in class can coexist with unresolved fact disagreements; neither high agreement nor repeated UNKNOWN agreement certifies correct effects.

Reports keep planned/paired actions, missing initial reviews, missing references, unresolved adjudications, blinding-compromised actions and synthetic exclusions. Missing/unresolved references never silently enter the accuracy denominator as correct or clean. Metrics and planned/paired counts are stratified by supplied domain, effect type, policy boundary and evidence condition, including strata with no eligible references. Sampling and provenance can bias the paired subset and require researcher review.

Action-level ratios are explicitly action-level. Distinct case/target/cluster counts are separate; no majority vote or single case/target accuracy is invented. Repeated actions within a cluster stay together in resampling. A declared case/target, exact source case/target instance or known template/paraphrase/scenario/parent ancestry split across clusters is flagged and suppresses inferential intervals. Renaming declared unit IDs cannot bypass known source lineage. Actual source-case and target-instance counts are reported separately from declared units; fresh fixture instances do not establish independent target designs. This conservative flag can overgroup independent scenarios; resolving it requires a reviewed cluster definition, not an automatic waiver.

Confidence intervals are optional, explicitly configured whole-cluster percentile resampling with supplied seed, replicate count and confidence level. Sampling draws clusters with replacement and retains every member action; it never treats repeated attempts as independent Bernoulli trials. Fewer than two clusters or an original undefined denominator yields a null interval. Undefined resampled denominators are counted; intervals from defined replicates are labeled conditional/descriptive, not silently passed off as unconditional coverage. Small or invalid clusters, selection bias and non-independent labels invalidate inferential interpretation. No approved scientific CI method or threshold is selected by an example/default; operational use needs the protocol's clustering/sampling decisions.

Low-level arithmetic functions are reusable mathematics, always provenance-labeled and NOT_CERTIFIED. The main report only offers human-reference comparisons when the independent-review purpose, all protocol references, two blinded human-origin submissions and any required human adjudication are supplied. Software cannot authenticate those declarations. Even then status is REFERENCE_COMPARISON_ONLY and certification remains NOT_INDEPENDENTLY_CERTIFIED. Without eligible labels, accuracy/agreement are null and status PENDING. `--calibration` explicitly marks synthetic-only numeric tests; it never upgrades them to human evidence.

## Integrity, challenges and readiness

The study reuses PR-05 exclusive append-only recording, canonical serialization, content addresses and seals. Original evidence, reviewer views, instructions, predictions, decisions and adjudication remain traceable. View/policy/source substitutions, altered labels, duplicate imports, stale guidance clearance, missing seals and wrong expected seal fail checks. Hashes establish consistency, not source truth, privacy, human authorship, independence, signatures or protection against an OS owner. Whole-archive replacement/recomputed chains cannot be disproved without independently retained pins and custody.

Synthetic controls exercise commits, blocks, legitimate effects, failures/rollbacks, partial/timeouts, missing/delayed/contradictory evidence, cross-action/target contamination and UNKNOWN. Hand-calculated matrices/kappa/cluster tests challenge denominator and independence behavior. Deliberately incorrect policies can hide a violation; a fabricated receipt from an explicitly trusted reader can cause a false confirmation. These are **synthetic dependency-failure demonstrations**, not measured error rates or newly discovered empirical vulnerabilities. They show why independent policy/source validation is essential; no oracle or legacy behavior is silently changed to erase the discrepancy.

PR-05 golden controls and disabled-detector sentinel remain unchanged and run with the full suite. Existing locked Python 3.11/3.12 research CI automatically includes all new tests. No dependencies or prior workflows need changes.

Independent validation remains PENDING until actual reviewers, source authenticity/custody, reviewed policy, sampling/clustering, blinding clearance, adjudication rules, acceptance thresholds and retention/release are approved and genuine labels exist. No reviewer engagement messages were sent. No empirical validation score, independent target or human label is fabricated. Engineering review does not authorize PR-07 or the main experiment.
