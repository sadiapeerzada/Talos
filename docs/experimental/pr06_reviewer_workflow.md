# PR-06 reviewer and coordinator procedure

**Status: prepared procedure only. No reviewers have been recruited or assigned by this PR.** The test pseudonyms, clearances and labels are explicitly synthetic. They are not people, approvals or independent reference data.

## Before any real assignment

The researcher/custodian must supply and record:

- Two genuinely independent reviewers and a separate adjudicator; conflict-of-interest/identity checks and pseudonym mapping held outside reviewer bundles. Pseudonym differences alone are insufficient.
- An approved prospective sampling plan and scope. Stratification must cover all five outcomes and evidence failures without using oracle predictions as reference truth. Define action/case/target units and correlation clusters; do not silently declare repeats independent or assign a held-out cohort.
- Exact reviewed policy/rule text, principal/task context and authoritative source custody/finality/completeness evidence. Missing PR-05 finalization or source proof needs a reviewed supplement or an abstention, not an invented receipt.
- Blinding/redaction inspection of every packet and linked source, including arbitrary text and identifiers. No oracle outputs, generated expectations, arm identities or another initial label may be visible.
- An annotation rubric/training procedure, uncertainty rules, adjudication policy, explicit acceptance thresholds and an approved analysis/CI method. Do not tune thresholds after seeing outcomes.
- Authorized sharing channel, account isolation, retention/access/redaction policy, data-owner permission and distribution/license decisions. The private archive contains predictions and identity linkage.

The [protocol template](pr06_protocol_template.json) deliberately contains null placeholders. It is not an approved protocol or valid populated configuration.

## Coordinator preparation

Use a new private study directory. Preserve original PR-05 sealed archives and separately pinned seals. `from_archive` takes an exact named action, explicitly supplied policy material and private key (at least 32 bytes), plus supplied case/target/cluster/stratum identifiers. It verifies offline replay and returns:

- `packet`: transformed, candidate blinded evidence for curator inspection;
- `sample`: private source/action/policy/cluster identity linkage;
- `prediction`: private unchanged PR-01 verdict artifact;
- `private_linkage`: pseudonym-to-original mapping, never distributed.

This is evidence preparation, not automatic sample selection or ground truth generation. Original raw evidence stays in the source archive. Do not distribute the returned dictionary or private study to reviewers.

Create the ledger with `Study.create(path, protocol, prepared, assignments)`. All objects use versioned Pydantic contracts in `talos.validation.models`. Assignments must cover the same packet for both raters, use opaque assignment IDs (`assignment-` plus 32 hex characters) and have timezone-aware timestamps. No labels are created by this call. Guidance and predictions become immutable content-addressed artifacts before annotation begins.

After inspecting the full candidate view and frozen instructions, supply a `Clearance` with exact packet and instructions SHA-256 and the actual curator review reference. A clearance is a declaration; the coordinator is responsible for its authenticity. Export each reviewer to a separate new directory outside the coordinator-private archive:

```sh
python -m talos.validation export /private/study ASSIGNMENT_ID /handoff/reviewer-bundle \
  --clearance /private/clearance.json
```

The bundle has only their assignment, evidence packet, case-neutral instructions and blank submission template. Distribute only that directory through the approved channel. No reviewer may access coordinator storage or the other reviewer's bundle/submission. No email/chat is sent automatically.

## Each reviewer

Read `instructions.json`, policy/principal/task material, evidence and limitations. Independently judge authorization, actual effect, violation, completeness, finality and custody. Cite exact evidence IDs and rule versions, record confidence/uncertainty, and explicitly choose a reference category. Do not assume a fixture's intended success or the presence of a tool call establishes committed impact. Report missing evidence and use UNKNOWN when necessary.

Fill `submission-template.json` manually. `origin=human_supplied` is only for an actual human-authored review; synthetic tests must remain synthetic_test. Fill actual authorship/reference and timezone-aware timestamps. Record blinding loss honestly; it is retained and excluded from eligible comparison. Software must not generate or impersonate these judgments.

Return only your own completed JSON. Coordinator imports an immutable snapshot:

```sh
python -m talos.validation submit /private/study /incoming/own-submission.json
```

The import checks assignment, pseudonym, exact evidence/policy identity, disclosed view/guidance and chronology. A duplicate or changed replacement is rejected. Preserve mistaken originals and follow an explicit amended study/protocol if a correction is needed.

## Adjudicator

Do not inspect initial labels until both raters have submitted. Then the coordinator may export the adjudication view:

```sh
python -m talos.validation adjudication-view /private/study SAMPLE_ID
```

It includes the common evidence, both original decisions/hashes and explicit core-fact/category disagreements, without the oracle prediction or arm. Resolve the disagreement through actual evidence review; request a new versioned evidence packet if additional source material is required. Record authorship, time, both original hashes, final explicit reference facts/category, blinding status and rationale. Disclose any accidental oracle/arm exposure; the affected final reference is excluded rather than treated as an independent judgment. The assigned adjudicator must differ from both raters. Original decisions remain intact.

```sh
python -m talos.validation adjudicate /private/study /incoming/adjudication.json
```

Matching categories with contradictory facts do not automatically resolve a case. Confidence and reasoning may differ without a core fact/category disagreement; those original fields remain available for review. No automated majority vote or invented consensus is performed.

## Freeze and compare

```sh
python -m talos.validation seal /private/study
python -m talos.validation report /private/study --expected-seal RECORDED_SEAL
```

Optional resampling requires explicit choices, for example `--resamples N --seed S --confidence C`, after a reviewed cluster/sampling design. Without genuine eligible references the report stays PENDING with null accuracy, explicit missing counts and no independent certification. Synthetic numeric tests require the explicit `--calibration` flag and remain engineering-only.

Researcher review must assess label authenticity/independence, sampling bias, source truth, adjudication, uncertainty, missing cells and acceptance thresholds. No automatic “PR-01 independently validated” status exists. Preserve the complete original reference, prediction and adjudication artifacts and any rejected/amended-version provenance under the approved retention policy.
