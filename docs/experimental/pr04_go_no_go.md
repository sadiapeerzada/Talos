# PR-04 engineering GO / NO-GO

2026-11-18. **GO for review of passive PR-04 engineering. NO-GO for empirical campaigns, independent held-out claims or starting PR-05 without a separate review/request.**

## Baseline and custody

- Repository: sadiapeerzada/Talos. Branch: `research/pr-04-portable-corpus`.
- PR-03 [#17](https://github.com/sadiapeerzada/Talos/pull/17) confirmed merged through GitHub metadata; merge `eeba84d4e40be53e8cbce101a8e4ecfad7dd467c` is in fetched main.
- Exact latest remote main base at restored implementation: `6662e00948d8f71c9a6c37f45bbebc872971e791` (includes merged README-only PR #18).
- Isolated checkout `/tmp/talos-pr04` (`/private/tmp/talos-pr04` equivalent on Darwin). Missing temporary session files were recreated on the existing PR-04 branch; no original checkout changes were incorporated.
- SHA-256 checks: **all 118 pre-existing tracked files identical to base**; all four original dirty/untracked user files identical to their entry fingerprints. Talos-35, every historical result, previous oracle/profile/target code, legacy scoring and manuscript/publication artifacts remain unchanged.
- Original user files excluded: `talos/report_native.md`, `talos/talos/sample_agents/policy.py`, `talos/talos/sample_agents/langchain_server.py`, `talos/talos/sample_agents/langchain_server.py.bak`.
- Final plan SHA-256: `116cd01f21b1ab28654dfe03c08f2100134d68d4a4830092c240277410c26d53`; original roadmap: `ec5589fdad267ce1d1c7964c67d7b8a6d898458762b2b5a2e6d42ebed4416202`.

## Delivered acceptance evidence

- Versioned schemas and manifest-pinned source JSON; immutable case identity, attribution, creation method and review status, duplicate/version/reference checks and serialization.
- 12 explicit authored/derived synthetic cases, 24 helpdesk/document bindings. These are fixture counts, not vulnerabilities or independent observations. No independently supplied cases or human labels are claimed.
- Direct/indirect surfaces, authorization/tool/workflow boundaries and benign/blocked/UNKNOWN controls; expected outcomes are conditional observer-only contracts.
- PR-02 roles/profile classifications drive compatibility; unfamiliar/renamed tools, unknown permission/trust, conflicts and unavailable delivery/evidence handled conservatively.
- Proposed actor/argument packets match actual PR-03 schemas without executing an environment. No default prompt/poison adapter is claimed: all shipped default plans are UNKNOWN.
- Exact versus conceptual taxonomy crosswalk with dated primary-source locators, pinned MITRE revision and OWASP retrieval limitations.
- Complete split identity and target context checks; family/template/paraphrase/text/ancestry/target/schema leakage diagnostics. Every shipped case UNASSIGNED; zero issues is never independent approval.
- Same common public pool for future arms, private observer contract separate, possible topology projection excludes observed paths and private audit/policy labels. No scheduler, budgets or feedback implementation.

See [implementation and limitations](pr04_corpus.md) and [pre-implementation decision ledger](pr04_decisions.md).

## Offline verification

Final full suite: **409 passed, 1 pre-existing Starlette/httpx deprecation warning** (291 unchanged prior tests + 118 new passive corpus tests). Focused suite: **118 passed**. Tests do not deliver corpus payloads, invoke tools through these cases or label empirical outcomes. Existing regression suite retains its local synthetic target/scan controls.

Environment: Darwin arm64, existing Python 3.13.7 / pytest 9.1.1 environment, no dependency installations or upgrades. API keys/proxies removed; external socket connections blocked; existing fixture servers use loopback. Original global learning/dashboard store is isolated to `/tmp/talos-pr04-state`. No new target/model calls, inference, security scans or attack campaigns were performed by corpus code/tests. Source-document web retrieval and GitHub operations are provenance/repository access, not target evaluations.

Focused command, cwd isolated repository:

```sh
PYTHONPATH=/tmp/talos-pr04/talos /Users/sadiapeerzada/Talos/talos/.venv/bin/python -m pytest talos/tests/test_portable_corpus.py -q
```

Final complete command, cwd isolated repository:

```sh
env -u ANTHROPIC_API_KEY -u GROQ_API_KEY -u OPENAI_API_KEY -u LANGSMITH_API_KEY -u LANGCHAIN_API_KEY -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY LANGSMITH_TRACING=false PYTHONPATH=/tmp/talos-pr04-support:/tmp/talos-pr04/talos /Users/sadiapeerzada/Talos/talos/.venv/bin/python -m pytest talos/tests/ -v
```

The temporary support module is outside the repository and inherited by existing fixture subprocesses. It redirects `talos.storage` default paths to the fresh temporary store and rejects non-loopback socket connect/connect_ex destinations. It is a regression guard, not a production network sandbox. Hosted Python 3.11/3.12 CI is separate and must be checked on the PR; this local run does not claim those environments passed.

Packaging: the existing test virtualenv lacks setuptools, so its first no-build-isolation wheel attempt failed with BackendUnavailable. No packages were installed. The existing system Python (setuptools 83.0.0, wheel 0.46.3) successfully built using:

```sh
/usr/local/bin/python3 -m pip wheel --no-index --no-deps --no-build-isolation --wheel-dir /tmp/pr04-wheels ./talos
```

All five JSON resources are in the wheel. Extracted-wheel import from `/tmp` with `PYTHONPATH=/tmp/pr04-wheel-check` loads 12 cases, 24 bindings, eight category entries and UNASSIGNED splits without source-checkout imports. Wheel build artifacts remain untracked/ignored and are not research data.

## Identity records

Canonical manifest values (content identity, not independent validity):

```json
{
  "schema_version": "talos.corpus-manifest.v1",
  "corpus_version": "Talos-Portable-1.0",
  "corpus_sha256": "efee9fed44936ab09dc74b049abdc95622f3a6ab215dbf63b8f6dc02e0571801",
  "taxonomy_sha256": "e58b0084cc684203d6f47388d93493dd7ec4e437c78de8f94869163aa459df9b",
  "case_hashes": {
    "TP1-DIRECT": "cf8f7f84f8ca863f49f1b7cff08e3e0865a0dccac2bb5578415522b4d4868089",
    "TP1-TOOL-DATA": "8542c9c56b06321a0ec4fb17e16625f26b000898ab88b6398ca8dac8bc9a7794",
    "TP1-DOCUMENT-DATA": "facb44d2b5f1d0e86dc5bd77833008925ea8a21c7856bc1f4d4c466e76b856ef",
    "TP1-AUTH-SPOOF": "7a3769f936e4eb4a0f8e310b74a4188f13cd2aa4593799be55df7b49ccac7b8a",
    "TP1-TOOL-EFFECT": "160142663d7156a01dfe3d4944df3fbdc47eb7103d2bc04641f90bed5d2a02f5",
    "TP1-WORKFLOW": "0802632d11f36a7510891c204d17b83fea7145008de882e0656c7bb35a953707",
    "TP1-DISCLOSURE": "04ba895dcb8e62cdb377d08e8ce5da817ae1e753eed8d315d1ff25b8db9ed5c5",
    "TP1-QUOTED": "5a0ad2396c2d4a07dc53b6525e1549ab12a84787ecb07791ddbd9f49aceae43d",
    "TP1-AUTHORIZED": "5bbc4dac18847aab7e12044af0ccf96ccb204f9f1dcf41ffcd08e81d537f07f6",
    "TP1-BLOCKED": "d6bc34278e6b35e4757b6b633e4ab9a6e9f7ccb256c853e74f2017e68ea1c171",
    "TP1-NO-EVIDENCE": "37977c327a7d1ad18f7c1bf06a80eb24bcefd779f238164b018c819c8da5c1b4",
    "TP1-DIRECT-PARAPHRASE": "26f1b1af10765d8aea1c729d0fa3d038f888b3a55c1699de753f12b2a48262d7"
  },
  "bindings_sha256": "90d40e426386216d9d233ba79ce250f85054b8dc679af0bde255d02fe651573c",
  "split_sha256": "6784bbc7e2f5ef58fd1fe4688ef2057039cac51d3542c4db57641e2ccbcaea2e"
}
```

Raw byte SHA-256 fingerprints for source fixtures/test:

```json
{
  "talos/talos/corpus/data/cases.json": "18348205499867e6cb8ea6adc555c2f13585393c27146c6f966371d887a548de",
  "talos/talos/corpus/data/bindings.json": "e7264db453ec5734fd61f9c9f9b91c11a79f4fb0273560b03e44182405079a38",
  "talos/talos/corpus/data/split.json": "78d001d6d7d233d52e54487e4956f408e465f5eed117f3281bc3a7001bf5e8ac",
  "talos/talos/corpus/data/taxonomy.json": "e55d4c7555c96a1ed9fe2fd5950b4008169e0ca4b2ea20965cc8bc710e0e17e0",
  "talos/tests/test_portable_corpus.py": "2b28e41bdb02a4e472e14248d23dca8d340649d25c09bfea990bfdad644385e5"
}
```

## Human decisions and limits

**No blocker prevents this bounded engineering submission.** Operational evaluation remains blocked pending reviewed target custody, actor policies, effect-reader trust/finality and delivery capabilities; case applicability/exclusions and denominators; root-cause/family clustering; allowed attacker information, budgets and feedback; independent case/label custody; source/fixture licensing and approved frozen DEV/TEST cohort. No approvals, independent validity or held-out selection were invented.

The corpus is small, public and synthetic. Structural checks can miss semantic leakage and overflag schema overlap. Profiles and proposed arguments are not an arbitrary JSON Schema interpreter or authenticated authority. Public graph projection is a narrow proposed information view, not an approved threat model. Independent labels, operational adapters, immutable run recorder, equal-budget arms and real-model studies remain later gates. No PR-05 work, numeric risk redefinition, historical changes or manuscript/figure work was performed.

## Complete final test transcript

```text
============================= test session starts ==============================
platform darwin -- Python 3.13.7, pytest-9.1.1, pluggy-1.6.0 -- /Users/sadiapeerzada/Talos/talos/.venv/bin/python
cachedir: .pytest_cache
rootdir: /private/tmp/talos-pr04/talos
configfile: pyproject.toml
plugins: anyio-4.14.2, langsmith-0.10.7
collecting ... collected 409 items

talos/tests/test_adapters_parity.py::test_tool_specs_match PASSED        [  0%]
talos/tests/test_adapters_parity.py::test_benign_lookup_matches PASSED   [  0%]
talos/tests/test_adapters_parity.py::test_indirect_injection_matches PASSED [  0%]
talos/tests/test_adapters_parity.py::test_two_turn_permission_escalation_matches PASSED [  0%]
talos/tests/test_adaptive_generation.py::test_adaptive_generation_emits_refinement_variants PASSED [  1%]
talos/tests/test_adaptive_generation.py::test_adaptive_scan_runs_more_than_base_template_count PASSED [  1%]
talos/tests/test_autofix.py::test_autofix_cycle_strictly_reduces_risk_score_end_to_end PASSED [  1%]
talos/tests/test_autofix.py::test_autofix_cycle_closes_the_specific_refund_overage_exploit_class PASSED [  1%]
talos/tests/test_autofix.py::test_autofix_result_summary_lines_match_the_real_numbers PASSED [  2%]
talos/tests/test_autofix.py::test_hardening_strategies_registry_covers_every_exploit_class_talos_can_produce PASSED [  2%]
talos/tests/test_autofix.py::test_hardened_native_server_flag_actually_wraps_the_brain PASSED [  2%]
talos/tests/test_blast_radius.py::test_no_evidence_yields_zero_exposure_but_one_tool PASSED [  2%]
talos/tests/test_blast_radius.py::test_refund_overage_produces_dollar_exposure PASSED [  3%]
talos/tests/test_blast_radius.py::test_single_record_email_exposure_is_counted_concretely PASSED [  3%]
talos/tests/test_blast_radius.py::test_bulk_export_is_flagged_qualitatively_not_fabricated_as_a_count PASSED [  3%]
talos/tests/test_blast_radius.py::test_unverified_action_chain_widens_tools_affected PASSED [  3%]
talos/tests/test_blast_radius.py::test_worst_case_across_multiple_variants_is_taken PASSED [  4%]
talos/tests/test_blast_radius.py::test_blast_radius_is_json_serializable_and_defaults_present PASSED [  4%]
talos/tests/test_ci_risk_gate.py::test_higher_score_is_a_regression PASSED [  4%]
talos/tests/test_ci_risk_gate.py::test_lower_score_passes_and_reports_improvement PASSED [  4%]
talos/tests/test_ci_risk_gate.py::test_equal_score_passes PASSED         [  5%]
talos/tests/test_ci_risk_gate.py::test_one_point_regression_still_fails PASSED [  5%]
talos/tests/test_ci_risk_gate.py::test_result_is_a_plain_dataclass_with_expected_fields PASSED [  5%]
talos/tests/test_ci_risk_gate.py::test_committed_baseline_file_is_valid_and_loadable PASSED [  5%]
talos/tests/test_ci_risk_gate.py::test_ci_gate_end_to_end_against_a_real_scan PASSED [  6%]
talos/tests/test_controlled_targets.py::test_benign_task_completes_with_expected_response_and_real_state[vulnerable-lookup_employee] PASSED [  6%]
talos/tests/test_controlled_targets.py::test_benign_task_completes_with_expected_response_and_real_state[vulnerable-approve_expense] PASSED [  6%]
talos/tests/test_controlled_targets.py::test_benign_task_completes_with_expected_response_and_real_state[vulnerable-grant_access] PASSED [  6%]
talos/tests/test_controlled_targets.py::test_benign_task_completes_with_expected_response_and_real_state[vulnerable-notify_manager] PASSED [  7%]
talos/tests/test_controlled_targets.py::test_benign_task_completes_with_expected_response_and_real_state[vulnerable-search_documents] PASSED [  7%]
talos/tests/test_controlled_targets.py::test_benign_task_completes_with_expected_response_and_real_state[vulnerable-read_document] PASSED [  7%]
talos/tests/test_controlled_targets.py::test_benign_task_completes_with_expected_response_and_real_state[vulnerable-share_document] PASSED [  7%]
talos/tests/test_controlled_targets.py::test_benign_task_completes_with_expected_response_and_real_state[vulnerable-set_editor] PASSED [  8%]
talos/tests/test_controlled_targets.py::test_benign_task_completes_with_expected_response_and_real_state[hardened-lookup_employee] PASSED [  8%]
talos/tests/test_controlled_targets.py::test_benign_task_completes_with_expected_response_and_real_state[hardened-approve_expense] PASSED [  8%]
talos/tests/test_controlled_targets.py::test_benign_task_completes_with_expected_response_and_real_state[hardened-grant_access] PASSED [  8%]
talos/tests/test_controlled_targets.py::test_benign_task_completes_with_expected_response_and_real_state[hardened-notify_manager] PASSED [  9%]
talos/tests/test_controlled_targets.py::test_benign_task_completes_with_expected_response_and_real_state[hardened-search_documents] PASSED [  9%]
talos/tests/test_controlled_targets.py::test_benign_task_completes_with_expected_response_and_real_state[hardened-read_document] PASSED [  9%]
talos/tests/test_controlled_targets.py::test_benign_task_completes_with_expected_response_and_real_state[hardened-share_document] PASSED [  9%]
talos/tests/test_controlled_targets.py::test_benign_task_completes_with_expected_response_and_real_state[hardened-set_editor] PASSED [ 10%]
talos/tests/test_controlled_targets.py::test_seeded_denied_action_commits_only_in_vulnerable_variant[vulnerable-approve_expense] PASSED [ 10%]
talos/tests/test_controlled_targets.py::test_seeded_denied_action_commits_only_in_vulnerable_variant[vulnerable-grant_access] PASSED [ 10%]
talos/tests/test_controlled_targets.py::test_seeded_denied_action_commits_only_in_vulnerable_variant[vulnerable-notify_manager] PASSED [ 10%]
talos/tests/test_controlled_targets.py::test_seeded_denied_action_commits_only_in_vulnerable_variant[vulnerable-share_document] PASSED [ 11%]
talos/tests/test_controlled_targets.py::test_seeded_denied_action_commits_only_in_vulnerable_variant[vulnerable-set_editor] PASSED [ 11%]
talos/tests/test_controlled_targets.py::test_seeded_denied_action_commits_only_in_vulnerable_variant[vulnerable-read_document] PASSED [ 11%]
talos/tests/test_controlled_targets.py::test_seeded_denied_action_commits_only_in_vulnerable_variant[hardened-approve_expense] PASSED [ 11%]
talos/tests/test_controlled_targets.py::test_seeded_denied_action_commits_only_in_vulnerable_variant[hardened-grant_access] PASSED [ 11%]
talos/tests/test_controlled_targets.py::test_seeded_denied_action_commits_only_in_vulnerable_variant[hardened-notify_manager] PASSED [ 12%]
talos/tests/test_controlled_targets.py::test_seeded_denied_action_commits_only_in_vulnerable_variant[hardened-share_document] PASSED [ 12%]
talos/tests/test_controlled_targets.py::test_seeded_denied_action_commits_only_in_vulnerable_variant[hardened-set_editor] PASSED [ 12%]
talos/tests/test_controlled_targets.py::test_seeded_denied_action_commits_only_in_vulnerable_variant[hardened-read_document] PASSED [ 12%]
talos/tests/test_controlled_targets.py::test_fault_controls_preserve_effects_and_abstain_when_unobservable[it-helpdesk-failed_tool-ATTEMPTED-False] PASSED [ 13%]
talos/tests/test_controlled_targets.py::test_fault_controls_preserve_effects_and_abstain_when_unobservable[it-helpdesk-rollback_before_commit-ATTEMPTED-False] PASSED [ 13%]
talos/tests/test_controlled_targets.py::test_fault_controls_preserve_effects_and_abstain_when_unobservable[it-helpdesk-partial_commit-UNKNOWN-True] PASSED [ 13%]
talos/tests/test_controlled_targets.py::test_fault_controls_preserve_effects_and_abstain_when_unobservable[it-helpdesk-timeout-UNKNOWN-False] PASSED [ 13%]
talos/tests/test_controlled_targets.py::test_fault_controls_preserve_effects_and_abstain_when_unobservable[it-helpdesk-missing_audit-UNKNOWN-True] PASSED [ 14%]
talos/tests/test_controlled_targets.py::test_fault_controls_preserve_effects_and_abstain_when_unobservable[it-helpdesk-delayed_audit-UNKNOWN-True] PASSED [ 14%]
talos/tests/test_controlled_targets.py::test_fault_controls_preserve_effects_and_abstain_when_unobservable[it-helpdesk-contradictory_audit-UNKNOWN-True] PASSED [ 14%]
talos/tests/test_controlled_targets.py::test_fault_controls_preserve_effects_and_abstain_when_unobservable[it-helpdesk-unrelated_state_change-UNKNOWN-True] PASSED [ 14%]
talos/tests/test_controlled_targets.py::test_fault_controls_preserve_effects_and_abstain_when_unobservable[document-management-failed_tool-ATTEMPTED-False] PASSED [ 15%]
talos/tests/test_controlled_targets.py::test_fault_controls_preserve_effects_and_abstain_when_unobservable[document-management-rollback_before_commit-ATTEMPTED-False] PASSED [ 15%]
talos/tests/test_controlled_targets.py::test_fault_controls_preserve_effects_and_abstain_when_unobservable[document-management-partial_commit-UNKNOWN-True] PASSED [ 15%]
talos/tests/test_controlled_targets.py::test_fault_controls_preserve_effects_and_abstain_when_unobservable[document-management-timeout-UNKNOWN-False] PASSED [ 15%]
talos/tests/test_controlled_targets.py::test_fault_controls_preserve_effects_and_abstain_when_unobservable[document-management-missing_audit-UNKNOWN-True] PASSED [ 16%]
talos/tests/test_controlled_targets.py::test_fault_controls_preserve_effects_and_abstain_when_unobservable[document-management-delayed_audit-UNKNOWN-True] PASSED [ 16%]
talos/tests/test_controlled_targets.py::test_fault_controls_preserve_effects_and_abstain_when_unobservable[document-management-contradictory_audit-UNKNOWN-True] PASSED [ 16%]
talos/tests/test_controlled_targets.py::test_fault_controls_preserve_effects_and_abstain_when_unobservable[document-management-unrelated_state_change-UNKNOWN-True] PASSED [ 16%]
talos/tests/test_controlled_targets.py::test_delayed_evidence_requires_final_publication_without_reexecuting[it-helpdesk] PASSED [ 17%]
talos/tests/test_controlled_targets.py::test_delayed_evidence_requires_final_publication_without_reexecuting[document-management] PASSED [ 17%]
talos/tests/test_controlled_targets.py::test_failed_or_incomplete_reset_revokes_all_confirmation[it-helpdesk-failed_reset] PASSED [ 17%]
talos/tests/test_controlled_targets.py::test_failed_or_incomplete_reset_revokes_all_confirmation[it-helpdesk-incomplete_reset] PASSED [ 17%]
talos/tests/test_controlled_targets.py::test_failed_or_incomplete_reset_revokes_all_confirmation[document-management-failed_reset] PASSED [ 18%]
talos/tests/test_controlled_targets.py::test_failed_or_incomplete_reset_revokes_all_confirmation[document-management-incomplete_reset] PASSED [ 18%]
talos/tests/test_controlled_targets.py::test_business_reset_is_deterministic_but_contexts_and_instances_are_unique[it-helpdesk] PASSED [ 18%]
talos/tests/test_controlled_targets.py::test_business_reset_is_deterministic_but_contexts_and_instances_are_unique[document-management] PASSED [ 18%]
talos/tests/test_controlled_targets.py::test_replayed_or_cross_context_receipts_cannot_confirm[it-helpdesk-target_id-wrong-target] PASSED [ 19%]
talos/tests/test_controlled_targets.py::test_replayed_or_cross_context_receipts_cannot_confirm[it-helpdesk-actor_id-manager] PASSED [ 19%]
talos/tests/test_controlled_targets.py::test_replayed_or_cross_context_receipts_cannot_confirm[it-helpdesk-scenario_id-other] PASSED [ 19%]
talos/tests/test_controlled_targets.py::test_replayed_or_cross_context_receipts_cannot_confirm[it-helpdesk-run_id-other] PASSED [ 19%]
talos/tests/test_controlled_targets.py::test_replayed_or_cross_context_receipts_cannot_confirm[it-helpdesk-repeat_id-other] PASSED [ 20%]
talos/tests/test_controlled_targets.py::test_replayed_or_cross_context_receipts_cannot_confirm[it-helpdesk-authorization_context_id-other] PASSED [ 20%]
talos/tests/test_controlled_targets.py::test_replayed_or_cross_context_receipts_cannot_confirm[it-helpdesk-action_id-other] PASSED [ 20%]
talos/tests/test_controlled_targets.py::test_replayed_or_cross_context_receipts_cannot_confirm[document-management-target_id-wrong-target] PASSED [ 20%]
talos/tests/test_controlled_targets.py::test_replayed_or_cross_context_receipts_cannot_confirm[document-management-actor_id-manager] PASSED [ 21%]
talos/tests/test_controlled_targets.py::test_replayed_or_cross_context_receipts_cannot_confirm[document-management-scenario_id-other] PASSED [ 21%]
talos/tests/test_controlled_targets.py::test_replayed_or_cross_context_receipts_cannot_confirm[document-management-run_id-other] PASSED [ 21%]
talos/tests/test_controlled_targets.py::test_replayed_or_cross_context_receipts_cannot_confirm[document-management-repeat_id-other] PASSED [ 21%]
talos/tests/test_controlled_targets.py::test_replayed_or_cross_context_receipts_cannot_confirm[document-management-authorization_context_id-other] PASSED [ 22%]
talos/tests/test_controlled_targets.py::test_replayed_or_cross_context_receipts_cannot_confirm[document-management-action_id-other] PASSED [ 22%]
talos/tests/test_controlled_targets.py::test_argument_digest_and_missing_store_record_beat_forged_success_claim[it-helpdesk] PASSED [ 22%]
talos/tests/test_controlled_targets.py::test_argument_digest_and_missing_store_record_beat_forged_success_claim[document-management] PASSED [ 22%]
talos/tests/test_controlled_targets.py::test_target_response_cannot_erase_or_fabricate_stored_evidence[it-helpdesk] PASSED [ 22%]
talos/tests/test_controlled_targets.py::test_target_response_cannot_erase_or_fabricate_stored_evidence[document-management] PASSED [ 23%]
talos/tests/test_controlled_targets.py::test_duplicate_action_identity_never_reexecutes_or_overwrites[it-helpdesk] PASSED [ 23%]
talos/tests/test_controlled_targets.py::test_duplicate_action_identity_never_reexecutes_or_overwrites[document-management] PASSED [ 23%]
talos/tests/test_controlled_targets.py::test_audit_and_snapshots_bind_every_identity_and_are_not_exposed_on_tool_handle[it-helpdesk] PASSED [ 23%]
talos/tests/test_controlled_targets.py::test_audit_and_snapshots_bind_every_identity_and_are_not_exposed_on_tool_handle[document-management] PASSED [ 24%]
talos/tests/test_controlled_targets.py::test_reader_connections_are_readonly_and_journals_append_only[it-helpdesk] PASSED [ 24%]
talos/tests/test_controlled_targets.py::test_reader_connections_are_readonly_and_journals_append_only[document-management] PASSED [ 24%]
talos/tests/test_controlled_targets.py::test_profile_policy_graph_and_state_oracle_are_compatible[it-helpdesk] PASSED [ 24%]
talos/tests/test_controlled_targets.py::test_profile_policy_graph_and_state_oracle_are_compatible[document-management] PASSED [ 25%]
talos/tests/test_controlled_targets.py::test_bound_principal_cannot_be_overridden_by_arguments PASSED [ 25%]
talos/tests/test_controlled_targets.py::test_editor_access_is_usable_and_scope_policy_uses_pre_action_snapshot PASSED [ 25%]
talos/tests/test_controlled_targets.py::test_closed_or_missing_store_cannot_supply_confirmed_evidence PASSED [ 25%]
talos/tests/test_controlled_targets.py::test_targets_do_not_import_legacy_fixture_data_or_model_clients PASSED [ 26%]
talos/tests/test_controlled_targets.py::test_unexpected_reset_storage_exception_revokes_existing_readers_and_handles[it-helpdesk] PASSED [ 26%]
talos/tests/test_controlled_targets.py::test_unexpected_reset_storage_exception_revokes_existing_readers_and_handles[document-management] PASSED [ 26%]
talos/tests/test_controlled_targets.py::test_reset_failure_cannot_be_repaired_by_late_audit_only[it-helpdesk] PASSED [ 26%]
talos/tests/test_controlled_targets.py::test_reset_failure_cannot_be_repaired_by_late_audit_only[document-management] PASSED [ 27%]
talos/tests/test_controlled_targets.py::test_helpdesk_policy_enforces_limit_team_and_root_boundaries_individually PASSED [ 27%]
talos/tests/test_controlled_targets.py::test_document_owner_still_cannot_share_restricted_content_to_other_team PASSED [ 27%]
talos/tests/test_controlled_targets.py::test_synthetic_sink_boundary_holds_even_in_vulnerable_variant[it-helpdesk-notify_manager-args0] PASSED [ 27%]
talos/tests/test_controlled_targets.py::test_synthetic_sink_boundary_holds_even_in_vulnerable_variant[document-management-share_document-args1] PASSED [ 28%]
talos/tests/test_controlled_targets.py::test_operator_snapshot_provenance_and_offline_verdict_replay_are_exact[it-helpdesk] PASSED [ 28%]
talos/tests/test_controlled_targets.py::test_operator_snapshot_provenance_and_offline_verdict_replay_are_exact[document-management] PASSED [ 28%]
talos/tests/test_cross_agent_injection.py::test_upstream_summarizer_auto_escalates_urgent_complaints PASSED [ 28%]
talos/tests/test_cross_agent_injection.py::test_upstream_summarizer_does_not_escalate_a_benign_message PASSED [ 29%]
talos/tests/test_cross_agent_injection.py::test_cross_agent_chain_succeeds_where_single_hop_control_fails PASSED [ 29%]
talos/tests/test_cross_agent_injection.py::test_cross_agent_finding_scores_correctly_through_talos_real_pipeline PASSED [ 29%]
talos/tests/test_cross_agent_injection.py::test_cross_agent_injection_is_registered_in_the_taxonomy PASSED [ 29%]
talos/tests/test_cross_agent_injection.py::test_cross_agent_injection_finding_gets_a_valid_remediation_patch PASSED [ 30%]
talos/tests/test_dashboard.py::test_dashboard_root_serves_html PASSED    [ 30%]
talos/tests/test_dashboard.py::test_dashboard_scan_streams_progress_and_final_report PASSED [ 30%]
talos/tests/test_dashboard.py::test_medium_and_low_severity_counts_stay_consistent_with_critical_and_high PASSED [ 30%]
talos/tests/test_dashboard.py::test_monitor_runs_recurring_scans_and_exposes_history PASSED [ 31%]
talos/tests/test_dashboard.py::test_monitoring_manager_persists_history_and_alerts PASSED [ 31%]
talos/tests/test_external_langchain_agent.py::test_tools_endpoint_matches_langchain_adapter_contract PASSED [ 31%]
talos/tests/test_external_langchain_agent.py::test_agent_endpoint_round_trip_executes_a_real_tool_call PASSED [ 31%]
talos/tests/test_external_langchain_agent.py::test_talos_langchain_adapter_discovers_and_drives_this_target_end_to_end PASSED [ 32%]
talos/tests/test_external_langchain_agent.py::test_tool_graph_classifier_detects_financial_and_external_comm_and_free_text_on_this_independent_target PASSED [ 32%]
talos/tests/test_graph_parity.py::test_graph_identical_across_adapters PASSED [ 32%]
talos/tests/test_graph_parity.py::test_graph_classifies_known_tools_correctly PASSED [ 32%]
talos/tests/test_learning.py::test_learning_store_summarizes_and_ranks_findings PASSED [ 33%]
talos/tests/test_learning.py::test_learning_hints_prioritize_future_batches PASSED [ 33%]
talos/tests/test_legacy_scoring_capture.py::test_legacy_capture_preserves_original_return_schema_and_every_repeat PASSED [ 33%]
talos/tests/test_legacy_scoring_capture.py::test_exact_count_is_not_reconstructed_from_rounded_rate PASSED [ 33%]
talos/tests/test_legacy_scoring_capture.py::test_legacy_minimum_one_repeat_behavior_preserved[0] PASSED [ 33%]
talos/tests/test_legacy_scoring_capture.py::test_legacy_minimum_one_repeat_behavior_preserved[-1] PASSED [ 34%]
talos/tests/test_legacy_scoring_capture.py::test_legacy_minimum_one_repeat_behavior_preserved[1] PASSED [ 34%]
talos/tests/test_legacy_scoring_capture.py::test_legacy_tool_error_not_silently_rejudged_as_v2 PASSED [ 34%]
talos/tests/test_legacy_scoring_capture.py::test_legacy_packet_rejects_fabricated_counts PASSED [ 34%]
talos/tests/test_legacy_scoring_capture.py::test_versioned_legacy_risk_alias_preserves_formula PASSED [ 35%]
talos/tests/test_legacy_scoring_capture.py::test_mcnemar_still_uses_at_least_one_success_when_majority_failed PASSED [ 35%]
talos/tests/test_legacy_scoring_capture.py::test_legacy_capture_snapshots_a_reused_agent_turn PASSED [ 35%]
talos/tests/test_portable_corpus.py::test_package_integrity_and_roundtrip PASSED [ 35%]
talos/tests/test_portable_corpus.py::test_invalid_cases_rejected[case_id-bad] PASSED [ 36%]
talos/tests/test_portable_corpus.py::test_invalid_cases_rejected[revision-0] PASSED [ 36%]
talos/tests/test_portable_corpus.py::test_invalid_cases_rejected[revision-True] PASSED [ 36%]
talos/tests/test_portable_corpus.py::test_invalid_cases_rejected[revision-1] PASSED [ 36%]
talos/tests/test_portable_corpus.py::test_invalid_cases_rejected[schema_version-talos.attack-case.v2] PASSED [ 37%]
talos/tests/test_portable_corpus.py::test_invalid_cases_rejected[corpus_version-Talos-35] PASSED [ 37%]
talos/tests/test_portable_corpus.py::test_invalid_cases_rejected[family-unrecognized] PASSED [ 37%]
talos/tests/test_portable_corpus.py::test_invalid_cases_rejected[entry_surface-web-whatever] PASSED [ 37%]
talos/tests/test_portable_corpus.py::test_invalid_cases_rejected[objective-] PASSED [ 38%]
talos/tests/test_portable_corpus.py::test_invalid_cases_rejected[intended_policy_boundary-] PASSED [ 38%]
talos/tests/test_portable_corpus.py::test_invalid_cases_rejected[prerequisites-value10] PASSED [ 38%]
talos/tests/test_portable_corpus.py::test_invalid_cases_rejected[scenario_ancestry-value11] PASSED [ 38%]
talos/tests/test_portable_corpus.py::test_invalid_cases_rejected[tool_requirements-value12] PASSED [ 39%]
talos/tests/test_portable_corpus.py::test_invalid_cases_rejected[stimuli-value13] PASSED [ 39%]
talos/tests/test_portable_corpus.py::test_invalid_cases_rejected[expected_observable_evidence-value14] PASSED [ 39%]
talos/tests/test_portable_corpus.py::test_invalid_cases_rejected[expectations-value15] PASSED [ 39%]
talos/tests/test_portable_corpus.py::test_invalid_cases_rejected[kind-measured_success] PASSED [ 40%]
talos/tests/test_portable_corpus.py::test_invalid_cases_rejected[parent_case_ids-value17] PASSED [ 40%]
talos/tests/test_portable_corpus.py::test_invalid_cases_rejected[public_parameter_names-value18] PASSED [ 40%]
talos/tests/test_portable_corpus.py::test_invalid_cases_rejected[public_parameter_names-value19] PASSED [ 40%]
talos/tests/test_portable_corpus.py::test_invalid_cases_rejected[observed_outcome-CONFIRMED] PASSED [ 41%]
talos/tests/test_portable_corpus.py::test_invalid_cases_rejected[risk_score-100] PASSED [ 41%]
talos/tests/test_portable_corpus.py::test_unsafe_or_undeclared_template_fields[{missing}] PASSED [ 41%]
talos/tests/test_portable_corpus.py::test_unsafe_or_undeclared_template_fields[{action_tool.name}] PASSED [ 41%]
talos/tests/test_portable_corpus.py::test_unsafe_or_undeclared_template_fields[{action_tool[0]}] PASSED [ 42%]
talos/tests/test_portable_corpus.py::test_unsafe_or_undeclared_template_fields[{action_tool!r}] PASSED [ 42%]
talos/tests/test_portable_corpus.py::test_unsafe_or_undeclared_template_fields[{action_tool:>20}] PASSED [ 42%]
talos/tests/test_portable_corpus.py::test_unsafe_or_undeclared_template_fields[{] PASSED [ 42%]
talos/tests/test_portable_corpus.py::test_unsafe_or_undeclared_template_fields[{}] PASSED [ 43%]
talos/tests/test_portable_corpus.py::test_literal_braces_are_preserved_once PASSED [ 43%]
talos/tests/test_portable_corpus.py::test_corpus_identity_validation[duplicate] PASSED [ 43%]
talos/tests/test_portable_corpus.py::test_corpus_identity_validation[missing_parent] PASSED [ 43%]
talos/tests/test_portable_corpus.py::test_corpus_identity_validation[cycle] PASSED [ 44%]
talos/tests/test_portable_corpus.py::test_corpus_identity_validation[bad_hash] PASSED [ 44%]
talos/tests/test_portable_corpus.py::test_corpus_identity_validation[wrong_version] PASSED [ 44%]
talos/tests/test_portable_corpus.py::test_revision_continuity PASSED     [ 44%]
talos/tests/test_portable_corpus.py::test_invalid_crosswalks[source] PASSED [ 44%]
talos/tests/test_portable_corpus.py::test_invalid_crosswalks[edition] PASSED [ 45%]
talos/tests/test_portable_corpus.py::test_invalid_crosswalks[category] PASSED [ 45%]
talos/tests/test_portable_corpus.py::test_invalid_crosswalks[exact] PASSED [ 45%]
talos/tests/test_portable_corpus.py::test_invalid_crosswalks[duplicate] PASSED [ 45%]
talos/tests/test_portable_corpus.py::test_taxonomy_registry_references[duplicate_source] PASSED [ 46%]
talos/tests/test_portable_corpus.py::test_taxonomy_registry_references[unknown_source] PASSED [ 46%]
talos/tests/test_portable_corpus.py::test_taxonomy_registry_references[duplicate_category] PASSED [ 46%]
talos/tests/test_portable_corpus.py::test_cross_domain_passive_compatibility[it-helpdesk-0] PASSED [ 46%]
talos/tests/test_portable_corpus.py::test_cross_domain_passive_compatibility[it-helpdesk-1] PASSED [ 47%]
talos/tests/test_portable_corpus.py::test_cross_domain_passive_compatibility[it-helpdesk-2] PASSED [ 47%]
talos/tests/test_portable_corpus.py::test_cross_domain_passive_compatibility[it-helpdesk-3] PASSED [ 47%]
talos/tests/test_portable_corpus.py::test_cross_domain_passive_compatibility[it-helpdesk-4] PASSED [ 47%]
talos/tests/test_portable_corpus.py::test_cross_domain_passive_compatibility[it-helpdesk-5] PASSED [ 48%]
talos/tests/test_portable_corpus.py::test_cross_domain_passive_compatibility[it-helpdesk-6] PASSED [ 48%]
talos/tests/test_portable_corpus.py::test_cross_domain_passive_compatibility[it-helpdesk-7] PASSED [ 48%]
talos/tests/test_portable_corpus.py::test_cross_domain_passive_compatibility[it-helpdesk-8] PASSED [ 48%]
talos/tests/test_portable_corpus.py::test_cross_domain_passive_compatibility[it-helpdesk-9] PASSED [ 49%]
talos/tests/test_portable_corpus.py::test_cross_domain_passive_compatibility[it-helpdesk-10] PASSED [ 49%]
talos/tests/test_portable_corpus.py::test_cross_domain_passive_compatibility[it-helpdesk-11] PASSED [ 49%]
talos/tests/test_portable_corpus.py::test_cross_domain_passive_compatibility[document-management-0] PASSED [ 49%]
talos/tests/test_portable_corpus.py::test_cross_domain_passive_compatibility[document-management-1] PASSED [ 50%]
talos/tests/test_portable_corpus.py::test_cross_domain_passive_compatibility[document-management-2] PASSED [ 50%]
talos/tests/test_portable_corpus.py::test_cross_domain_passive_compatibility[document-management-3] PASSED [ 50%]
talos/tests/test_portable_corpus.py::test_cross_domain_passive_compatibility[document-management-4] PASSED [ 50%]
talos/tests/test_portable_corpus.py::test_cross_domain_passive_compatibility[document-management-5] PASSED [ 51%]
talos/tests/test_portable_corpus.py::test_cross_domain_passive_compatibility[document-management-6] PASSED [ 51%]
talos/tests/test_portable_corpus.py::test_cross_domain_passive_compatibility[document-management-7] PASSED [ 51%]
talos/tests/test_portable_corpus.py::test_cross_domain_passive_compatibility[document-management-8] PASSED [ 51%]
talos/tests/test_portable_corpus.py::test_cross_domain_passive_compatibility[document-management-9] PASSED [ 52%]
talos/tests/test_portable_corpus.py::test_cross_domain_passive_compatibility[document-management-10] PASSED [ 52%]
talos/tests/test_portable_corpus.py::test_cross_domain_passive_compatibility[document-management-11] PASSED [ 52%]
talos/tests/test_portable_corpus.py::test_profile_uncertainty_and_inapplicability[permissions-UNKNOWN] PASSED [ 52%]
talos/tests/test_portable_corpus.py::test_profile_uncertainty_and_inapplicability[conflict-UNKNOWN] PASSED [ 53%]
talos/tests/test_portable_corpus.py::test_profile_uncertainty_and_inapplicability[missing_schema-UNKNOWN] PASSED [ 53%]
talos/tests/test_portable_corpus.py::test_profile_uncertainty_and_inapplicability[effects-UNKNOWN] PASSED [ 53%]
talos/tests/test_portable_corpus.py::test_profile_uncertainty_and_inapplicability[missing_capability-UNKNOWN] PASSED [ 53%]
talos/tests/test_portable_corpus.py::test_profile_uncertainty_and_inapplicability[mismatch-INAPPLICABLE] PASSED [ 54%]
talos/tests/test_portable_corpus.py::test_profile_uncertainty_and_inapplicability[missing_tool-INAPPLICABLE] PASSED [ 54%]
talos/tests/test_portable_corpus.py::test_renamed_tools_and_schema_properties PASSED [ 54%]
talos/tests/test_portable_corpus.py::test_common_public_pool_has_no_observer_metadata PASSED [ 54%]
talos/tests/test_portable_corpus.py::test_binding_integrity[corpus] PASSED [ 55%]
talos/tests/test_portable_corpus.py::test_binding_integrity[case] PASSED [ 55%]
talos/tests/test_portable_corpus.py::test_binding_integrity[slots] PASSED [ 55%]
talos/tests/test_portable_corpus.py::test_binding_integrity[parameters] PASSED [ 55%]
talos/tests/test_portable_corpus.py::test_binding_integrity[duplicate] PASSED [ 55%]
talos/tests/test_portable_corpus.py::test_no_approved_split_is_shipped PASSED [ 56%]
talos/tests/test_portable_corpus.py::test_declared_and_transitive_leakage_axes PASSED [ 56%]
talos/tests/test_portable_corpus.py::test_split_invalid_or_incomplete_context[hash] PASSED [ 56%]
talos/tests/test_portable_corpus.py::test_split_invalid_or_incomplete_context[missing] PASSED [ 56%]
talos/tests/test_portable_corpus.py::test_split_invalid_or_incomplete_context[extra] PASSED [ 57%]
talos/tests/test_portable_corpus.py::test_split_invalid_or_incomplete_context[profiles] PASSED [ 57%]
talos/tests/test_portable_corpus.py::test_split_invalid_or_incomplete_context[split_name] PASSED [ 57%]
talos/tests/test_portable_corpus.py::test_split_invalid_or_incomplete_context[approval] PASSED [ 57%]
talos/tests/test_portable_corpus.py::test_split_invalid_or_incomplete_context[threshold] PASSED [ 58%]
talos/tests/test_portable_corpus.py::test_schema_and_text_renaming_leakage PASSED [ 58%]
talos/tests/test_portable_corpus.py::test_identical_normalized_payload_detected_across_distinct_declared_families PASSED [ 58%]
talos/tests/test_portable_corpus.py::test_loader_rejects_tampered_package[manifest] PASSED [ 58%]
talos/tests/test_portable_corpus.py::test_loader_rejects_tampered_package[taxonomy] PASSED [ 59%]
talos/tests/test_portable_corpus.py::test_loader_rejects_tampered_package[case] PASSED [ 59%]
talos/tests/test_portable_corpus.py::test_no_customer_service_dependencies_or_execution_imports PASSED [ 59%]
talos/tests/test_portable_corpus.py::test_all_proposed_fixture_arguments_match_actual_schemas_without_execution[it-helpdesk] PASSED [ 59%]
talos/tests/test_portable_corpus.py::test_all_proposed_fixture_arguments_match_actual_schemas_without_execution[document-management] PASSED [ 60%]
talos/tests/test_portable_corpus.py::test_conditional_case_contracts[direct_surface] PASSED [ 60%]
talos/tests/test_portable_corpus.py::test_conditional_case_contracts[indirect_surface] PASSED [ 60%]
talos/tests/test_portable_corpus.py::test_conditional_case_contracts[workflow_step] PASSED [ 60%]
talos/tests/test_portable_corpus.py::test_conditional_case_contracts[control_attack] PASSED [ 61%]
talos/tests/test_portable_corpus.py::test_conditional_case_contracts[derived_parent] PASSED [ 61%]
talos/tests/test_portable_corpus.py::test_conditional_case_contracts[review_reference] PASSED [ 61%]
talos/tests/test_portable_corpus.py::test_conditional_case_contracts[unknown_contract] PASSED [ 61%]
talos/tests/test_portable_corpus.py::test_conditional_case_contracts[unknown_role] PASSED [ 62%]
talos/tests/test_portable_corpus.py::test_trust_dependent_tool_output_requirement PASSED [ 62%]
talos/tests/test_portable_corpus.py::test_tampered_model_instances_cannot_bypass_plan_validation PASSED [ 62%]
talos/tests/test_portable_corpus.py::test_graph_projection_retains_possible_edges_without_private_evidence PASSED [ 62%]
talos/tests/test_portable_corpus.py::test_graph_arm_rejects_private_fields_unknown_inventory_and_observed_paths[graph0] PASSED [ 63%]
talos/tests/test_portable_corpus.py::test_graph_arm_rejects_private_fields_unknown_inventory_and_observed_paths[graph1] PASSED [ 63%]
talos/tests/test_portable_corpus.py::test_graph_arm_rejects_private_fields_unknown_inventory_and_observed_paths[graph2] PASSED [ 63%]
talos/tests/test_portable_corpus.py::test_graph_arm_rejects_private_fields_unknown_inventory_and_observed_paths[graph3] PASSED [ 63%]
talos/tests/test_portable_corpus.py::test_leakage_rejects_missing_case_target_context PASSED [ 64%]
talos/tests/test_portable_corpus.py::test_binding_and_split_content_are_manifest_pinned[bindings.json] PASSED [ 64%]
talos/tests/test_portable_corpus.py::test_binding_and_split_content_are_manifest_pinned[split.json] PASSED [ 64%]
talos/tests/test_portable_oracle.py::test_unauthorized_commit_requires_matching_trusted_witness PASSED [ 64%]
talos/tests/test_portable_oracle.py::test_domain_neutral_tool_names[approve_expense_payment] PASSED [ 65%]
talos/tests/test_portable_oracle.py::test_domain_neutral_tool_names[publish_private_document] PASSED [ 65%]
talos/tests/test_portable_oracle.py::test_domain_neutral_tool_names[renamed_write_72] PASSED [ 65%]
talos/tests/test_portable_oracle.py::test_trusted_no_commit_outcomes[BLOCKED-BLOCKED] PASSED [ 65%]
talos/tests/test_portable_oracle.py::test_trusted_no_commit_outcomes[FAILED-ATTEMPTED] PASSED [ 66%]
talos/tests/test_portable_oracle.py::test_trusted_no_commit_outcomes[ROLLED_BACK-ATTEMPTED] PASSED [ 66%]
talos/tests/test_portable_oracle.py::test_trusted_no_commit_outcomes[NO_EFFECT-ATTEMPTED] PASSED [ 66%]
talos/tests/test_portable_oracle.py::test_legitimate_actions[COMMITTED] PASSED [ 66%]
talos/tests/test_portable_oracle.py::test_legitimate_actions[BLOCKED] PASSED [ 66%]
talos/tests/test_portable_oracle.py::test_legitimate_actions[FAILED] PASSED [ 67%]
talos/tests/test_portable_oracle.py::test_legitimate_actions[ROLLED_BACK] PASSED [ 67%]
talos/tests/test_portable_oracle.py::test_legitimate_actions[NO_EFFECT] PASSED [ 67%]
talos/tests/test_portable_oracle.py::test_request_only_is_attempted_with_uncertainty PASSED [ 67%]
talos/tests/test_portable_oracle.py::test_target_claim_cannot_self_certify_commit_or_safety[COMMITTED] PASSED [ 68%]
talos/tests/test_portable_oracle.py::test_target_claim_cannot_self_certify_commit_or_safety[BLOCKED] PASSED [ 68%]
talos/tests/test_portable_oracle.py::test_target_claim_cannot_self_certify_commit_or_safety[FAILED] PASSED [ 68%]
talos/tests/test_portable_oracle.py::test_target_claim_cannot_self_certify_commit_or_safety[ROLLED_BACK] PASSED [ 68%]
talos/tests/test_portable_oracle.py::test_target_claim_cannot_self_certify_commit_or_safety[UNKNOWN] PASSED [ 69%]
talos/tests/test_portable_oracle.py::test_authoritative_block_overrides_untrusted_commit_claim PASSED [ 69%]
talos/tests/test_portable_oracle.py::test_reader_receives_action_not_attacker_selected_receipt PASSED [ 69%]
talos/tests/test_portable_oracle.py::test_failure_and_rollback_without_no_commit_attestation_are_unknown[None-FAILED] PASSED [ 69%]
talos/tests/test_portable_oracle.py::test_failure_and_rollback_without_no_commit_attestation_are_unknown[None-ROLLED_BACK] PASSED [ 70%]
talos/tests/test_portable_oracle.py::test_failure_and_rollback_without_no_commit_attestation_are_unknown[None-BLOCKED] PASSED [ 70%]
talos/tests/test_portable_oracle.py::test_failure_and_rollback_without_no_commit_attestation_are_unknown[True-FAILED] PASSED [ 70%]
talos/tests/test_portable_oracle.py::test_failure_and_rollback_without_no_commit_attestation_are_unknown[True-ROLLED_BACK] PASSED [ 70%]
talos/tests/test_portable_oracle.py::test_failure_and_rollback_without_no_commit_attestation_are_unknown[True-BLOCKED] PASSED [ 71%]
talos/tests/test_portable_oracle.py::test_accepted_then_rolled_back_never_confirms PASSED [ 71%]
talos/tests/test_portable_oracle.py::test_rollback_does_not_erase_prior_committed_evidence PASSED [ 71%]
talos/tests/test_portable_oracle.py::test_missing_or_inconsistent_commit_witness[changes0] PASSED [ 71%]
talos/tests/test_portable_oracle.py::test_missing_or_inconsistent_commit_witness[changes1] PASSED [ 72%]
talos/tests/test_portable_oracle.py::test_missing_or_inconsistent_commit_witness[changes2] PASSED [ 72%]
talos/tests/test_portable_oracle.py::test_missing_or_inconsistent_commit_witness[changes3] PASSED [ 72%]
talos/tests/test_portable_oracle.py::test_missing_or_inconsistent_commit_witness[changes4] PASSED [ 72%]
talos/tests/test_portable_oracle.py::test_missing_or_inconsistent_commit_witness[changes5] PASSED [ 73%]
talos/tests/test_portable_oracle.py::test_missing_or_unknown_policy_and_evidence_never_imply_safety PASSED [ 73%]
talos/tests/test_portable_oracle.py::test_evidence_cannot_leak_across_contexts[target_id-other-target] PASSED [ 73%]
talos/tests/test_portable_oracle.py::test_evidence_cannot_leak_across_contexts[scenario_id-other-scenario] PASSED [ 73%]
talos/tests/test_portable_oracle.py::test_evidence_cannot_leak_across_contexts[run_id-other-run] PASSED [ 74%]
talos/tests/test_portable_oracle.py::test_evidence_cannot_leak_across_contexts[repeat_id-other-repeat] PASSED [ 74%]
talos/tests/test_portable_oracle.py::test_evidence_cannot_leak_across_contexts[actor_id-other-user] PASSED [ 74%]
talos/tests/test_portable_oracle.py::test_evidence_cannot_leak_across_contexts[tool_name-other-tool] PASSED [ 74%]
talos/tests/test_portable_oracle.py::test_evidence_cannot_leak_across_contexts[arguments-value6] PASSED [ 75%]
talos/tests/test_portable_oracle.py::test_evidence_cannot_leak_across_contexts[authorization_context_id-other-permissions] PASSED [ 75%]
talos/tests/test_portable_oracle.py::test_wrong_policy_binding_and_trace_binding_abstain PASSED [ 75%]
talos/tests/test_portable_oracle.py::test_duplicate_event_ids_abstain PASSED [ 75%]
talos/tests/test_portable_oracle.py::test_boundary_errors_and_invalid_responses_fail_closed[True-policy] PASSED [ 76%]
talos/tests/test_portable_oracle.py::test_boundary_errors_and_invalid_responses_fail_closed[True-evidence_reader] PASSED [ 76%]
talos/tests/test_portable_oracle.py::test_boundary_errors_and_invalid_responses_fail_closed[False-policy] PASSED [ 76%]
talos/tests/test_portable_oracle.py::test_boundary_errors_and_invalid_responses_fail_closed[False-evidence_reader] PASSED [ 76%]
talos/tests/test_portable_oracle.py::test_evidence_order_does_not_change_serialized_verdict PASSED [ 77%]
talos/tests/test_portable_oracle.py::test_invalid_schema_versions_statuses_trust_and_non_json_arguments_rejected PASSED [ 77%]
talos/tests/test_portable_oracle.py::test_portable_import_does_not_load_customer_service_fixtures PASSED [ 77%]
talos/tests/test_portable_oracle.py::test_exact_repeat_counts_and_full_outcomes_survive_json_round_trip PASSED [ 77%]
talos/tests/test_portable_oracle.py::test_empty_duplicate_and_mixed_repeat_series_rejected PASSED [ 77%]
talos/tests/test_portable_oracle.py::test_repeat_snapshot_does_not_retain_callers_mutable_arguments PASSED [ 78%]
talos/tests/test_portable_oracle.py::test_policy_cannot_mutate_action_used_for_evidence_binding PASSED [ 78%]
talos/tests/test_portable_oracle.py::test_nonfinite_state_and_nonboolean_effect_attestations_are_rejected PASSED [ 78%]
talos/tests/test_portable_oracle.py::test_repeat_deserialization_rejects_forged_counts_and_verdict_binding PASSED [ 78%]
talos/tests/test_portable_oracle.py::test_serialized_terminal_verdict_requires_policy_and_evidence_references PASSED [ 79%]
talos/tests/test_real_agent_hardening.py::test_refund_amount_is_clipped_to_order_total PASSED [ 79%]
talos/tests/test_real_agent_hardening.py::test_refund_blocked_after_prior_read_step PASSED [ 79%]
talos/tests/test_real_agent_hardening.py::test_refund_allowed_with_explicit_confirmation_and_no_prior_read PASSED [ 79%]
talos/tests/test_real_agent_hardening.py::test_email_to_external_domain_is_blocked_entirely PASSED [ 80%]
talos/tests/test_real_agent_hardening.py::test_email_to_allowed_domain_still_requires_fresh_authorization PASSED [ 80%]
talos/tests/test_real_agent_hardening.py::test_compound_refund_and_unauthorized_email_fails_closed_on_the_refund_too PASSED [ 80%]
talos/tests/test_real_agent_hardening.py::test_compound_request_with_allowed_email_domain_does_not_block_the_refund PASSED [ 80%]
talos/tests/test_real_agent_hardening.py::test_message_with_no_email_at_all_is_unaffected_by_the_compound_check PASSED [ 81%]
talos/tests/test_real_agent_hardening.py::test_non_sensitive_decisions_pass_through_untouched PASSED [ 81%]
talos/tests/test_real_agent_hardening.py::test_real_agent_server_tool_contract_matches_native_server PASSED [ 81%]
talos/tests/test_real_agent_hardening.py::test_llm_brain_supports_multiple_providers_without_code_changes PASSED [ 81%]
talos/tests/test_real_agent_hardening.py::test_groq_brain_backcompat_alias_still_works PASSED [ 82%]
talos/tests/test_real_agent_hardening.py::test_risk_score_weighting_and_clamping PASSED [ 82%]
talos/tests/test_real_agent_hardening.py::test_export_report_endpoint_returns_downloadable_markdown PASSED [ 82%]
talos/tests/test_remediation.py::test_refund_finding_emits_amount_capping_guard PASSED [ 82%]
talos/tests/test_remediation.py::test_email_finding_emits_domain_allowlist_guard PASSED [ 83%]
talos/tests/test_remediation.py::test_indirect_injection_emits_instruction_hierarchy_addendum PASSED [ 83%]
talos/tests/test_remediation.py::test_permission_escalation_emits_reauth_guard PASSED [ 83%]
talos/tests/test_remediation.py::test_unknown_exploit_class_still_emits_something_actionable PASSED [ 83%]
talos/tests/test_remediation.py::test_generated_patches_are_always_valid_python PASSED [ 84%]
talos/tests/test_replay.py::test_replay_is_a_complete_standalone_html_document PASSED [ 84%]
talos/tests/test_replay.py::test_replay_has_no_external_network_dependencies PASSED [ 84%]
talos/tests/test_replay.py::test_replay_contains_the_real_attack_message_and_evidence PASSED [ 84%]
talos/tests/test_replay.py::test_replay_contains_the_blast_radius_payoff_line PASSED [ 85%]
talos/tests/test_replay.py::test_replay_picks_the_successful_variant_when_multiple_exist PASSED [ 85%]
talos/tests/test_replay.py::test_replay_handles_a_finding_with_no_variants_gracefully PASSED [ 85%]
talos/tests/test_replay.py::test_replay_severity_color_differs_by_severity PASSED [ 85%]
talos/tests/test_replay.py::test_replay_escapes_message_content_to_avoid_html_injection PASSED [ 86%]
talos/tests/test_scan_end_to_end.py::test_generates_35_templates_across_7_classes PASSED [ 86%]
talos/tests/test_scan_end_to_end.py::test_scan_finds_all_exploit_classes PASSED [ 86%]
talos/tests/test_scan_end_to_end.py::test_adapters_produce_identical_deduplicated_findings PASSED [ 86%]
talos/tests/test_scan_end_to_end.py::test_over_refund_is_flagged_with_correct_overage PASSED [ 87%]
talos/tests/test_scan_end_to_end.py::test_exfiltration_email_flagged_as_external PASSED [ 87%]
talos/tests/test_target_profiles.py::test_fixture_semantic_classification_and_exact_toy_counts[documents] PASSED [ 87%]
talos/tests/test_target_profiles.py::test_fixture_semantic_classification_and_exact_toy_counts[operations] PASSED [ 87%]
talos/tests/test_target_profiles.py::test_fixture_semantic_classification_and_exact_toy_counts[ambiguous] PASSED [ 88%]
talos/tests/test_target_profiles.py::test_unknown_tools_never_default_to_readonly_or_public PASSED [ 88%]
talos/tests/test_target_profiles.py::test_renamed_tools_and_parameters_do_not_change_semantics_or_edges PASSED [ 88%]
talos/tests/test_target_profiles.py::test_conflicting_metadata_abstains_and_preserves_reasons_and_provenance PASSED [ 88%]
talos/tests/test_target_profiles.py::test_versions_json_roundtrip_and_nested_schema_preservation PASSED [ 88%]
talos/tests/test_target_profiles.py::test_invalid_metadata_references_are_rejected[unknown_evidence] PASSED [ 89%]
talos/tests/test_target_profiles.py::test_invalid_metadata_references_are_rejected[unknown_boundary] PASSED [ 89%]
talos/tests/test_target_profiles.py::test_invalid_metadata_references_are_rejected[unknown_capability] PASSED [ 89%]
talos/tests/test_target_profiles.py::test_invalid_metadata_references_are_rejected[unknown_flow_tool] PASSED [ 89%]
talos/tests/test_target_profiles.py::test_invalid_metadata_references_are_rejected[duplicate_tool] PASSED [ 90%]
talos/tests/test_target_profiles.py::test_invalid_metadata_references_are_rejected[duplicate_evidence] PASSED [ 90%]
talos/tests/test_target_profiles.py::test_invalid_metadata_references_are_rejected[false_independence] PASSED [ 90%]
talos/tests/test_target_profiles.py::test_invalid_metadata_references_are_rejected[nonfinite_schema] PASSED [ 90%]
talos/tests/test_target_profiles.py::test_empty_inventory_is_explicit_and_does_not_imply_security PASSED [ 91%]
talos/tests/test_target_profiles.py::test_parallel_possible_and_observed_edges_preserve_sources PASSED [ 91%]
talos/tests/test_target_profiles.py::test_static_graph_contains_no_observed_relationships PASSED [ 91%]
talos/tests/test_target_profiles.py::test_requests_blocks_and_ambiguity_do_not_become_execution_paths[REQUESTED] PASSED [ 91%]
talos/tests/test_target_profiles.py::test_requests_blocks_and_ambiguity_do_not_become_execution_paths[BLOCKED] PASSED [ 92%]
talos/tests/test_target_profiles.py::test_requests_blocks_and_ambiguity_do_not_become_execution_paths[UNKNOWN] PASSED [ 92%]
talos/tests/test_target_profiles.py::test_sequence_gaps_do_not_create_observed_edges PASSED [ 92%]
talos/tests/test_target_profiles.py::test_graph_export_is_stable_and_observed_step_input_order_is_irrelevant PASSED [ 92%]
talos/tests/test_target_profiles.py::test_cross_context_trace_paths_are_rejected[target_id-other] PASSED [ 93%]
talos/tests/test_target_profiles.py::test_cross_context_trace_paths_are_rejected[run_id-other] PASSED [ 93%]
talos/tests/test_target_profiles.py::test_cross_context_trace_paths_are_rejected[repeat_id-2] PASSED [ 93%]
talos/tests/test_target_profiles.py::test_cross_context_trace_paths_are_rejected[scenario_id-other] PASSED [ 93%]
talos/tests/test_target_profiles.py::test_forged_trace_bindings_and_duplicate_ids_are_rejected PASSED [ 94%]
talos/tests/test_target_profiles.py::test_profile_and_oracle_interoperate_without_auto_trusting_audit_capability PASSED [ 94%]
talos/tests/test_target_profiles.py::test_profile_policy_refuses_out_of_scope_action[a0] PASSED [ 94%]
talos/tests/test_target_profiles.py::test_profile_policy_refuses_out_of_scope_action[a1] PASSED [ 94%]
talos/tests/test_target_profiles.py::test_missing_conflicting_permissions_and_mismatched_policy_do_not_grant_authority PASSED [ 95%]
talos/tests/test_target_profiles.py::test_profile_snapshots_and_portable_import_have_no_fixture_dependency PASSED [ 95%]
talos/tests/test_target_profiles.py::test_schema_candidate_edge_precision_recall_against_toy_expectations[documents-expected0] PASSED [ 95%]
talos/tests/test_target_profiles.py::test_schema_candidate_edge_precision_recall_against_toy_expectations[operations-expected1] PASSED [ 95%]
talos/tests/test_target_profiles.py::test_schema_refs_are_preserved_but_never_fetched_or_assumed_safe PASSED [ 96%]
talos/tests/test_target_profiles.py::test_profile_cannot_self_declare_trusted_or_approved_integration PASSED [ 96%]
talos/tests/test_target_profiles.py::test_public_declaration_still_requires_an_explicit_policy_delegate PASSED [ 96%]
talos/tests/test_target_profiles.py::test_unchecked_profile_copy_is_revalidated PASSED [ 96%]
talos/tests/test_target_profiles.py::test_unknown_tool_mentioned_in_a_single_target_path_is_rejected PASSED [ 97%]
talos/tests/test_target_profiles.py::test_policy_delegate_must_bind_the_exact_action_and_rule_version PASSED [ 97%]
talos/tests/test_target_profiles.py::test_empty_inventory_parameters_remain_empty_and_duplicates_are_rejected PASSED [ 97%]
talos/tests/test_target_profiles.py::test_graph_snapshot_is_unchanged_when_caller_mutates_profile_schemas PASSED [ 97%]
talos/tests/test_target_profiles.py::test_observed_trace_content_is_hash_bound_without_becoming_impact_evidence PASSED [ 98%]
talos/tests/test_target_profiles.py::test_absent_permission_does_not_become_low_privilege_from_known_effect PASSED [ 98%]
talos/tests/test_target_profiles.py::test_conflicted_permissions_retain_boundary_provenance_for_review PASSED [ 98%]
talos/tests/test_taxonomy.py::test_taxonomy_version_matches_real_template_count PASSED [ 98%]
talos/tests/test_taxonomy.py::test_every_template_has_a_unique_citable_id PASSED [ 99%]
talos/tests/test_taxonomy.py::test_every_template_has_a_nonempty_description PASSED [ 99%]
talos/tests/test_taxonomy.py::test_seven_exploit_classes_with_five_templates_each PASSED [ 99%]
talos/tests/test_taxonomy.py::test_markdown_report_header_cites_taxonomy_version PASSED [ 99%]
talos/tests/test_taxonomy.py::test_readme_taxonomy_table_stays_in_sync_with_real_templates PASSED [100%]

=============================== warnings summary ===============================
../../../Users/sadiapeerzada/Talos/talos/.venv/lib/python3.13/site-packages/fastapi/testclient.py:1
  /Users/sadiapeerzada/Talos/talos/.venv/lib/python3.13/site-packages/fastapi/testclient.py:1: StarletteDeprecationWarning: Using `httpx` with `starlette.testclient` is deprecated; install `httpx2` instead.
    from starlette.testclient import TestClient as TestClient  # noqa

-- Docs: https://docs.pytest.org/en/stable/how-to/capture-warnings.html
======================== 409 passed, 1 warning in 9.68s ========================
```
