# PR-03 GO/NO-GO summary

Date: 2026-11-15. Base main: `1a4cc46d4f586ccf00cb7dc5c12578c0533da851`. Branch: `research/pr-03-controlled-targets`.

**GO: human review of the bounded PR-03 engineering implementation. NO-GO: empirical sweeps, live inference, external scans, claims of independent validation/generalization, or beginning PR-04 in this task.** This is an automated engineering record, not a researcher signature or an approval of the next phase.

Status vocabulary: VERIFIED means directly checked implementation/offline controls; PENDING means review/evidence remains incomplete; BLOCKED names a required human/input dependency. Passing engineering tests does not establish experimental validity.

| Acceptance condition | Status / evidence |
|---|---|
| Two different controlled domains | VERIFIED: helpdesk expense/team/entitlement/inbox state versus document content/ACL/share/editor/delivery state; separate domain policy/reducer modules |
| Benign tasks and vulnerable/hardened variants | VERIFIED in offline controls: eight explicit tasks complete with expected responses/state in both variants; seeded denied effects commit only in vulnerable controls and block in hardened controls |
| Real isolated synthetic transitions | VERIFIED: per-instance temporary SQLite store, atomic state/actions/audits, actual rollback savepoint; fixed synthetic recipients only; no external integration |
| Independently readable evidence | VERIFIED scoped implementation: operator-side read-only connections validate exact action, real state lineage, relevant transition, receipt/finality and reset proof; independent authorship/accuracy remains BLOCKED |
| Identity/authorization | VERIFIED fixture contracts: versioned policies, actor-bound tool handles, exact target/actor/context/scenario/run/repeat binding; metadata alone never grants permission |
| Missing/failed/contradictory evidence | VERIFIED: failed tools, rollback, partial writes, timeout, missing/delayed audits, contradictions and unrelated effects retain distinct state/finality and withhold false confirmation |
| Reset isolation | VERIFIED: deterministic seeds, fresh store IDs/reset generations; failed/incomplete/unexpected reset failures revoke old readers/handles; stale contexts cannot confirm |
| PR-01/02 compatibility | VERIFIED controls: unchanged oracle with explicit source selection; profile-bound policies; possible versus observed graph relations remain distinct |
| Legacy custody | VERIFIED by hashes: no pre-existing tracked file modified; original dirty/untracked files excluded and preserved |
| Source, policies and trust reviewed independently | BLOCKED: researcher/custodian review and actual independent human annotations are not supplied |
| Operational model/endpoint/budget authority | BLOCKED: no live/model study allowlist, compute budget, frozen protocol or G2–G7 signatures provided |
| Hosted CI | PENDING at submission; local results recorded below; do not infer remote success |

## Human decisions still required

1. Review the proposed synthetic authorization rules and effect/disclosure/reset semantics; approve or request a separately versioned correction. They are not assumed production policy.
2. Record actual target/source ownership, identity binding, custody and trusted-reader contract before operational research. Decide whether stronger process/OS isolation and independent implementation are needed.
3. Recruit real independent raters/adjudicator; review policy versus state evidence without treating code-generated expectations as independent labels.
4. Approve frozen DEV/TEST families, attack information boundaries, budgets, reset/order protocol and actual model access before any later study. Do not expose observer state/audits to attacker arms.
5. Select licensing, data-retention/redaction and release terms; no new legal or independent-review approval is fabricated here.
6. Review/merge this PR, then explicitly authorize the next bounded phase if desired. No PR-04 work is included or implicitly approved.

The finalized plan's E0 controls have local engineering evidence for this scope; E1–E8, authentic LLM-backed validation, independent targets and experiment approval remain unperformed. The original roadmap's real-model acceptance is not claimed complete. These two fixtures alone establish neither cross-domain generalization nor a credible efficacy estimate.

## Complete local validation

Final full suite: **291 passed, 1 warning in 8.89s**: all **199 unchanged existing tests** plus **92 new offline state/evidence controls**. Focused new suite: **92 passed in 0.67s**. The warning is the pre-existing Starlette/httpx TestClient deprecation. No final test failed. These are regression counts, not independent experimental cases, efficacy estimates or human labels.

Exact focused command, cwd `/private/tmp/talos-pr03`:

```sh
PYTHONPATH=/private/tmp/talos-pr03/talos /Users/sadiapeerzada/Talos/talos/.venv/bin/python -m pytest talos/tests/test_controlled_targets.py -q
```

Exact final full command, cwd `/private/tmp/talos-pr03/talos`:

```sh
env -u ANTHROPIC_API_KEY -u GROQ_API_KEY -u OPENAI_API_KEY -u LANGSMITH_API_KEY -u LANGCHAIN_API_KEY -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY LANGSMITH_TRACING=false PYTHONPATH=/private/tmp/talos-pr03-support:/private/tmp/talos-pr03/talos /Users/sadiapeerzada/Talos/talos/.venv/bin/python -m pytest tests/ -v > /private/tmp/talos-pr03-final.log 2>&1
```

Local environment: Darwin arm64 / Python 3.13.7 / pytest 9.1.1, reused existing virtualenv; no dependency installation/upgrade. Test-only support redirects legacy dashboard storage to `/private/tmp/talos-pr03-state` and rejects non-loopback socket connections. Model keys/proxies are removed. Loopback permission serves only existing regression fixture servers. No oracle/policy/assertion behavior is monkeypatched in the full-suite runner. Specific new failure tests explicitly inject controlled fixture faults and a simulated reset-storage exception.

All **105 pre-existing tracked paths** retain their baseline SHA-256. All four original modified/untracked user-file fingerprints are unchanged. Existing historical JSON/reports, risk definitions, PR-00/01/02, legacy tests and README are untouched. PR-03 consists of new files only; no manuscript or figure is written or modified. Document links and `git diff --check` pass.

Hosted CI is PENDING at submission (repository matrix Python 3.11/3.12); no remote result or minimum-version certification is invented. Opening the requested PR may trigger the existing CI fixture workflow; no standalone scan/risk-gate command or new empirical sweep was launched. All new target invocations were local synthetic engineering controls. Live-model/provider calls and external security scans: none.

## Source and fixture provenance

New code is repository-authored in this engineering session, not independently authored external-target code. The following SHA-256 values pin the reviewable source/test inputs. Runtime IDs use `synthetic:<domain>:<instance UUID>`, reset generations, caller scenario/run/repeat/action IDs and source-prefixed SQLite event/snapshot IDs; these identify ephemeral **test-only** packets, not experimental runs or validated root causes. The full test transcript below identifies every executed control. No reconstructed historical raw run is supplied.

| Path | SHA-256 |
|---|---|
| `talos/talos/targets/__init__.py` | `7486d14fab57cae09f2e662299af01e50e96f190ee8eeaa62c2e105edbf8a597` |
| `talos/talos/targets/documents.py` | `0f64eec61034f7c2f61217060bbf23cd0d69b3603ef7948bfba38a93e36410e9` |
| `talos/talos/targets/domains.py` | `352574d8cc3eaddc69db78605d01055a0436f1d8a2d1a417667af3881258f606` |
| `talos/talos/targets/environment.py` | `41b716f214658db752a3483e6747343c15ae77ecd759001629caebe7143be50c` |
| `talos/talos/targets/evidence.py` | `6c6dd52b4616658737a235d11ac04cb7d4e7b9187a462aa19140861b409cb5a2` |
| `talos/talos/targets/helpdesk.py` | `7a2fb3320b77a99b97468da35318a811a418cee0987f1d1c02e294767ede6468` |
| `talos/talos/targets/profiles.py` | `ba13cc0a662b4b9439bcbd037c4cadfbc0f39e5761c85d7dc222eede76bd3451` |
| `talos/talos/targets/store.py` | `38df0e90f303775e6c077063211dc7027c941a08d2799962c909129fed02889a` |
| `talos/tests/fixtures/controlled_target_tasks.json` | `577117cc48d11b272a71a7a0779314aa1eb045fffaab378af073c27c07b58fc8` |
| `talos/tests/test_controlled_targets.py` | `fca565dfeff90cf3a240085697c5a5ca530f0040f3860162dd35926f1f34b7a6` |

## Full final test transcript

<details>
<summary>291 passing tests and warning</summary>

```text
============================= test session starts ==============================
platform darwin -- Python 3.13.7, pytest-9.1.1, pluggy-1.6.0 -- /Users/sadiapeerzada/Talos/talos/.venv/bin/python
cachedir: .pytest_cache
rootdir: /private/tmp/talos-pr03/talos
configfile: pyproject.toml
plugins: anyio-4.14.2, langsmith-0.10.7
collecting ... collected 291 items

tests/test_adapters_parity.py::test_tool_specs_match PASSED              [  0%]
tests/test_adapters_parity.py::test_benign_lookup_matches PASSED         [  0%]
tests/test_adapters_parity.py::test_indirect_injection_matches PASSED    [  1%]
tests/test_adapters_parity.py::test_two_turn_permission_escalation_matches PASSED [  1%]
tests/test_adaptive_generation.py::test_adaptive_generation_emits_refinement_variants PASSED [  1%]
tests/test_adaptive_generation.py::test_adaptive_scan_runs_more_than_base_template_count PASSED [  2%]
tests/test_autofix.py::test_autofix_cycle_strictly_reduces_risk_score_end_to_end PASSED [  2%]
tests/test_autofix.py::test_autofix_cycle_closes_the_specific_refund_overage_exploit_class PASSED [  2%]
tests/test_autofix.py::test_autofix_result_summary_lines_match_the_real_numbers PASSED [  3%]
tests/test_autofix.py::test_hardening_strategies_registry_covers_every_exploit_class_talos_can_produce PASSED [  3%]
tests/test_autofix.py::test_hardened_native_server_flag_actually_wraps_the_brain PASSED [  3%]
tests/test_blast_radius.py::test_no_evidence_yields_zero_exposure_but_one_tool PASSED [  4%]
tests/test_blast_radius.py::test_refund_overage_produces_dollar_exposure PASSED [  4%]
tests/test_blast_radius.py::test_single_record_email_exposure_is_counted_concretely PASSED [  4%]
tests/test_blast_radius.py::test_bulk_export_is_flagged_qualitatively_not_fabricated_as_a_count PASSED [  5%]
tests/test_blast_radius.py::test_unverified_action_chain_widens_tools_affected PASSED [  5%]
tests/test_blast_radius.py::test_worst_case_across_multiple_variants_is_taken PASSED [  5%]
tests/test_blast_radius.py::test_blast_radius_is_json_serializable_and_defaults_present PASSED [  6%]
tests/test_ci_risk_gate.py::test_higher_score_is_a_regression PASSED     [  6%]
tests/test_ci_risk_gate.py::test_lower_score_passes_and_reports_improvement PASSED [  6%]
tests/test_ci_risk_gate.py::test_equal_score_passes PASSED               [  7%]
tests/test_ci_risk_gate.py::test_one_point_regression_still_fails PASSED [  7%]
tests/test_ci_risk_gate.py::test_result_is_a_plain_dataclass_with_expected_fields PASSED [  7%]
tests/test_ci_risk_gate.py::test_committed_baseline_file_is_valid_and_loadable PASSED [  8%]
tests/test_ci_risk_gate.py::test_ci_gate_end_to_end_against_a_real_scan PASSED [  8%]
tests/test_controlled_targets.py::test_benign_task_completes_with_expected_response_and_real_state[vulnerable-lookup_employee] PASSED [  8%]
tests/test_controlled_targets.py::test_benign_task_completes_with_expected_response_and_real_state[vulnerable-approve_expense] PASSED [  9%]
tests/test_controlled_targets.py::test_benign_task_completes_with_expected_response_and_real_state[vulnerable-grant_access] PASSED [  9%]
tests/test_controlled_targets.py::test_benign_task_completes_with_expected_response_and_real_state[vulnerable-notify_manager] PASSED [  9%]
tests/test_controlled_targets.py::test_benign_task_completes_with_expected_response_and_real_state[vulnerable-search_documents] PASSED [ 10%]
tests/test_controlled_targets.py::test_benign_task_completes_with_expected_response_and_real_state[vulnerable-read_document] PASSED [ 10%]
tests/test_controlled_targets.py::test_benign_task_completes_with_expected_response_and_real_state[vulnerable-share_document] PASSED [ 10%]
tests/test_controlled_targets.py::test_benign_task_completes_with_expected_response_and_real_state[vulnerable-set_editor] PASSED [ 11%]
tests/test_controlled_targets.py::test_benign_task_completes_with_expected_response_and_real_state[hardened-lookup_employee] PASSED [ 11%]
tests/test_controlled_targets.py::test_benign_task_completes_with_expected_response_and_real_state[hardened-approve_expense] PASSED [ 12%]
tests/test_controlled_targets.py::test_benign_task_completes_with_expected_response_and_real_state[hardened-grant_access] PASSED [ 12%]
tests/test_controlled_targets.py::test_benign_task_completes_with_expected_response_and_real_state[hardened-notify_manager] PASSED [ 12%]
tests/test_controlled_targets.py::test_benign_task_completes_with_expected_response_and_real_state[hardened-search_documents] PASSED [ 13%]
tests/test_controlled_targets.py::test_benign_task_completes_with_expected_response_and_real_state[hardened-read_document] PASSED [ 13%]
tests/test_controlled_targets.py::test_benign_task_completes_with_expected_response_and_real_state[hardened-share_document] PASSED [ 13%]
tests/test_controlled_targets.py::test_benign_task_completes_with_expected_response_and_real_state[hardened-set_editor] PASSED [ 14%]
tests/test_controlled_targets.py::test_seeded_denied_action_commits_only_in_vulnerable_variant[vulnerable-approve_expense] PASSED [ 14%]
tests/test_controlled_targets.py::test_seeded_denied_action_commits_only_in_vulnerable_variant[vulnerable-grant_access] PASSED [ 14%]
tests/test_controlled_targets.py::test_seeded_denied_action_commits_only_in_vulnerable_variant[vulnerable-notify_manager] PASSED [ 15%]
tests/test_controlled_targets.py::test_seeded_denied_action_commits_only_in_vulnerable_variant[vulnerable-share_document] PASSED [ 15%]
tests/test_controlled_targets.py::test_seeded_denied_action_commits_only_in_vulnerable_variant[vulnerable-set_editor] PASSED [ 15%]
tests/test_controlled_targets.py::test_seeded_denied_action_commits_only_in_vulnerable_variant[vulnerable-read_document] PASSED [ 16%]
tests/test_controlled_targets.py::test_seeded_denied_action_commits_only_in_vulnerable_variant[hardened-approve_expense] PASSED [ 16%]
tests/test_controlled_targets.py::test_seeded_denied_action_commits_only_in_vulnerable_variant[hardened-grant_access] PASSED [ 16%]
tests/test_controlled_targets.py::test_seeded_denied_action_commits_only_in_vulnerable_variant[hardened-notify_manager] PASSED [ 17%]
tests/test_controlled_targets.py::test_seeded_denied_action_commits_only_in_vulnerable_variant[hardened-share_document] PASSED [ 17%]
tests/test_controlled_targets.py::test_seeded_denied_action_commits_only_in_vulnerable_variant[hardened-set_editor] PASSED [ 17%]
tests/test_controlled_targets.py::test_seeded_denied_action_commits_only_in_vulnerable_variant[hardened-read_document] PASSED [ 18%]
tests/test_controlled_targets.py::test_fault_controls_preserve_effects_and_abstain_when_unobservable[it-helpdesk-failed_tool-ATTEMPTED-False] PASSED [ 18%]
tests/test_controlled_targets.py::test_fault_controls_preserve_effects_and_abstain_when_unobservable[it-helpdesk-rollback_before_commit-ATTEMPTED-False] PASSED [ 18%]
tests/test_controlled_targets.py::test_fault_controls_preserve_effects_and_abstain_when_unobservable[it-helpdesk-partial_commit-UNKNOWN-True] PASSED [ 19%]
tests/test_controlled_targets.py::test_fault_controls_preserve_effects_and_abstain_when_unobservable[it-helpdesk-timeout-UNKNOWN-False] PASSED [ 19%]
tests/test_controlled_targets.py::test_fault_controls_preserve_effects_and_abstain_when_unobservable[it-helpdesk-missing_audit-UNKNOWN-True] PASSED [ 19%]
tests/test_controlled_targets.py::test_fault_controls_preserve_effects_and_abstain_when_unobservable[it-helpdesk-delayed_audit-UNKNOWN-True] PASSED [ 20%]
tests/test_controlled_targets.py::test_fault_controls_preserve_effects_and_abstain_when_unobservable[it-helpdesk-contradictory_audit-UNKNOWN-True] PASSED [ 20%]
tests/test_controlled_targets.py::test_fault_controls_preserve_effects_and_abstain_when_unobservable[it-helpdesk-unrelated_state_change-UNKNOWN-True] PASSED [ 20%]
tests/test_controlled_targets.py::test_fault_controls_preserve_effects_and_abstain_when_unobservable[document-management-failed_tool-ATTEMPTED-False] PASSED [ 21%]
tests/test_controlled_targets.py::test_fault_controls_preserve_effects_and_abstain_when_unobservable[document-management-rollback_before_commit-ATTEMPTED-False] PASSED [ 21%]
tests/test_controlled_targets.py::test_fault_controls_preserve_effects_and_abstain_when_unobservable[document-management-partial_commit-UNKNOWN-True] PASSED [ 21%]
tests/test_controlled_targets.py::test_fault_controls_preserve_effects_and_abstain_when_unobservable[document-management-timeout-UNKNOWN-False] PASSED [ 22%]
tests/test_controlled_targets.py::test_fault_controls_preserve_effects_and_abstain_when_unobservable[document-management-missing_audit-UNKNOWN-True] PASSED [ 22%]
tests/test_controlled_targets.py::test_fault_controls_preserve_effects_and_abstain_when_unobservable[document-management-delayed_audit-UNKNOWN-True] PASSED [ 23%]
tests/test_controlled_targets.py::test_fault_controls_preserve_effects_and_abstain_when_unobservable[document-management-contradictory_audit-UNKNOWN-True] PASSED [ 23%]
tests/test_controlled_targets.py::test_fault_controls_preserve_effects_and_abstain_when_unobservable[document-management-unrelated_state_change-UNKNOWN-True] PASSED [ 23%]
tests/test_controlled_targets.py::test_delayed_evidence_requires_final_publication_without_reexecuting[it-helpdesk] PASSED [ 24%]
tests/test_controlled_targets.py::test_delayed_evidence_requires_final_publication_without_reexecuting[document-management] PASSED [ 24%]
tests/test_controlled_targets.py::test_failed_or_incomplete_reset_revokes_all_confirmation[it-helpdesk-failed_reset] PASSED [ 24%]
tests/test_controlled_targets.py::test_failed_or_incomplete_reset_revokes_all_confirmation[it-helpdesk-incomplete_reset] PASSED [ 25%]
tests/test_controlled_targets.py::test_failed_or_incomplete_reset_revokes_all_confirmation[document-management-failed_reset] PASSED [ 25%]
tests/test_controlled_targets.py::test_failed_or_incomplete_reset_revokes_all_confirmation[document-management-incomplete_reset] PASSED [ 25%]
tests/test_controlled_targets.py::test_business_reset_is_deterministic_but_contexts_and_instances_are_unique[it-helpdesk] PASSED [ 26%]
tests/test_controlled_targets.py::test_business_reset_is_deterministic_but_contexts_and_instances_are_unique[document-management] PASSED [ 26%]
tests/test_controlled_targets.py::test_replayed_or_cross_context_receipts_cannot_confirm[it-helpdesk-target_id-wrong-target] PASSED [ 26%]
tests/test_controlled_targets.py::test_replayed_or_cross_context_receipts_cannot_confirm[it-helpdesk-actor_id-manager] PASSED [ 27%]
tests/test_controlled_targets.py::test_replayed_or_cross_context_receipts_cannot_confirm[it-helpdesk-scenario_id-other] PASSED [ 27%]
tests/test_controlled_targets.py::test_replayed_or_cross_context_receipts_cannot_confirm[it-helpdesk-run_id-other] PASSED [ 27%]
tests/test_controlled_targets.py::test_replayed_or_cross_context_receipts_cannot_confirm[it-helpdesk-repeat_id-other] PASSED [ 28%]
tests/test_controlled_targets.py::test_replayed_or_cross_context_receipts_cannot_confirm[it-helpdesk-authorization_context_id-other] PASSED [ 28%]
tests/test_controlled_targets.py::test_replayed_or_cross_context_receipts_cannot_confirm[it-helpdesk-action_id-other] PASSED [ 28%]
tests/test_controlled_targets.py::test_replayed_or_cross_context_receipts_cannot_confirm[document-management-target_id-wrong-target] PASSED [ 29%]
tests/test_controlled_targets.py::test_replayed_or_cross_context_receipts_cannot_confirm[document-management-actor_id-manager] PASSED [ 29%]
tests/test_controlled_targets.py::test_replayed_or_cross_context_receipts_cannot_confirm[document-management-scenario_id-other] PASSED [ 29%]
tests/test_controlled_targets.py::test_replayed_or_cross_context_receipts_cannot_confirm[document-management-run_id-other] PASSED [ 30%]
tests/test_controlled_targets.py::test_replayed_or_cross_context_receipts_cannot_confirm[document-management-repeat_id-other] PASSED [ 30%]
tests/test_controlled_targets.py::test_replayed_or_cross_context_receipts_cannot_confirm[document-management-authorization_context_id-other] PASSED [ 30%]
tests/test_controlled_targets.py::test_replayed_or_cross_context_receipts_cannot_confirm[document-management-action_id-other] PASSED [ 31%]
tests/test_controlled_targets.py::test_argument_digest_and_missing_store_record_beat_forged_success_claim[it-helpdesk] PASSED [ 31%]
tests/test_controlled_targets.py::test_argument_digest_and_missing_store_record_beat_forged_success_claim[document-management] PASSED [ 31%]
tests/test_controlled_targets.py::test_target_response_cannot_erase_or_fabricate_stored_evidence[it-helpdesk] PASSED [ 32%]
tests/test_controlled_targets.py::test_target_response_cannot_erase_or_fabricate_stored_evidence[document-management] PASSED [ 32%]
tests/test_controlled_targets.py::test_duplicate_action_identity_never_reexecutes_or_overwrites[it-helpdesk] PASSED [ 32%]
tests/test_controlled_targets.py::test_duplicate_action_identity_never_reexecutes_or_overwrites[document-management] PASSED [ 33%]
tests/test_controlled_targets.py::test_audit_and_snapshots_bind_every_identity_and_are_not_exposed_on_tool_handle[it-helpdesk] PASSED [ 33%]
tests/test_controlled_targets.py::test_audit_and_snapshots_bind_every_identity_and_are_not_exposed_on_tool_handle[document-management] PASSED [ 34%]
tests/test_controlled_targets.py::test_reader_connections_are_readonly_and_journals_append_only[it-helpdesk] PASSED [ 34%]
tests/test_controlled_targets.py::test_reader_connections_are_readonly_and_journals_append_only[document-management] PASSED [ 34%]
tests/test_controlled_targets.py::test_profile_policy_graph_and_state_oracle_are_compatible[it-helpdesk] PASSED [ 35%]
tests/test_controlled_targets.py::test_profile_policy_graph_and_state_oracle_are_compatible[document-management] PASSED [ 35%]
tests/test_controlled_targets.py::test_bound_principal_cannot_be_overridden_by_arguments PASSED [ 35%]
tests/test_controlled_targets.py::test_editor_access_is_usable_and_scope_policy_uses_pre_action_snapshot PASSED [ 36%]
tests/test_controlled_targets.py::test_closed_or_missing_store_cannot_supply_confirmed_evidence PASSED [ 36%]
tests/test_controlled_targets.py::test_targets_do_not_import_legacy_fixture_data_or_model_clients PASSED [ 36%]
tests/test_controlled_targets.py::test_unexpected_reset_storage_exception_revokes_existing_readers_and_handles[it-helpdesk] PASSED [ 37%]
tests/test_controlled_targets.py::test_unexpected_reset_storage_exception_revokes_existing_readers_and_handles[document-management] PASSED [ 37%]
tests/test_controlled_targets.py::test_reset_failure_cannot_be_repaired_by_late_audit_only[it-helpdesk] PASSED [ 37%]
tests/test_controlled_targets.py::test_reset_failure_cannot_be_repaired_by_late_audit_only[document-management] PASSED [ 38%]
tests/test_controlled_targets.py::test_helpdesk_policy_enforces_limit_team_and_root_boundaries_individually PASSED [ 38%]
tests/test_controlled_targets.py::test_document_owner_still_cannot_share_restricted_content_to_other_team PASSED [ 38%]
tests/test_controlled_targets.py::test_synthetic_sink_boundary_holds_even_in_vulnerable_variant[it-helpdesk-notify_manager-args0] PASSED [ 39%]
tests/test_controlled_targets.py::test_synthetic_sink_boundary_holds_even_in_vulnerable_variant[document-management-share_document-args1] PASSED [ 39%]
tests/test_controlled_targets.py::test_operator_snapshot_provenance_and_offline_verdict_replay_are_exact[it-helpdesk] PASSED [ 39%]
tests/test_controlled_targets.py::test_operator_snapshot_provenance_and_offline_verdict_replay_are_exact[document-management] PASSED [ 40%]
tests/test_cross_agent_injection.py::test_upstream_summarizer_auto_escalates_urgent_complaints PASSED [ 40%]
tests/test_cross_agent_injection.py::test_upstream_summarizer_does_not_escalate_a_benign_message PASSED [ 40%]
tests/test_cross_agent_injection.py::test_cross_agent_chain_succeeds_where_single_hop_control_fails PASSED [ 41%]
tests/test_cross_agent_injection.py::test_cross_agent_finding_scores_correctly_through_talos_real_pipeline PASSED [ 41%]
tests/test_cross_agent_injection.py::test_cross_agent_injection_is_registered_in_the_taxonomy PASSED [ 41%]
tests/test_cross_agent_injection.py::test_cross_agent_injection_finding_gets_a_valid_remediation_patch PASSED [ 42%]
tests/test_dashboard.py::test_dashboard_root_serves_html PASSED          [ 42%]
tests/test_dashboard.py::test_dashboard_scan_streams_progress_and_final_report PASSED [ 42%]
tests/test_dashboard.py::test_medium_and_low_severity_counts_stay_consistent_with_critical_and_high PASSED [ 43%]
tests/test_dashboard.py::test_monitor_runs_recurring_scans_and_exposes_history PASSED [ 43%]
tests/test_dashboard.py::test_monitoring_manager_persists_history_and_alerts PASSED [ 43%]
tests/test_external_langchain_agent.py::test_tools_endpoint_matches_langchain_adapter_contract PASSED [ 44%]
tests/test_external_langchain_agent.py::test_agent_endpoint_round_trip_executes_a_real_tool_call PASSED [ 44%]
tests/test_external_langchain_agent.py::test_talos_langchain_adapter_discovers_and_drives_this_target_end_to_end PASSED [ 45%]
tests/test_external_langchain_agent.py::test_tool_graph_classifier_detects_financial_and_external_comm_and_free_text_on_this_independent_target PASSED [ 45%]
tests/test_graph_parity.py::test_graph_identical_across_adapters PASSED  [ 45%]
tests/test_graph_parity.py::test_graph_classifies_known_tools_correctly PASSED [ 46%]
tests/test_learning.py::test_learning_store_summarizes_and_ranks_findings PASSED [ 46%]
tests/test_learning.py::test_learning_hints_prioritize_future_batches PASSED [ 46%]
tests/test_legacy_scoring_capture.py::test_legacy_capture_preserves_original_return_schema_and_every_repeat PASSED [ 47%]
tests/test_legacy_scoring_capture.py::test_exact_count_is_not_reconstructed_from_rounded_rate PASSED [ 47%]
tests/test_legacy_scoring_capture.py::test_legacy_minimum_one_repeat_behavior_preserved[0] PASSED [ 47%]
tests/test_legacy_scoring_capture.py::test_legacy_minimum_one_repeat_behavior_preserved[-1] PASSED [ 48%]
tests/test_legacy_scoring_capture.py::test_legacy_minimum_one_repeat_behavior_preserved[1] PASSED [ 48%]
tests/test_legacy_scoring_capture.py::test_legacy_tool_error_not_silently_rejudged_as_v2 PASSED [ 48%]
tests/test_legacy_scoring_capture.py::test_legacy_packet_rejects_fabricated_counts PASSED [ 49%]
tests/test_legacy_scoring_capture.py::test_versioned_legacy_risk_alias_preserves_formula PASSED [ 49%]
tests/test_legacy_scoring_capture.py::test_mcnemar_still_uses_at_least_one_success_when_majority_failed PASSED [ 49%]
tests/test_legacy_scoring_capture.py::test_legacy_capture_snapshots_a_reused_agent_turn PASSED [ 50%]
tests/test_portable_oracle.py::test_unauthorized_commit_requires_matching_trusted_witness PASSED [ 50%]
tests/test_portable_oracle.py::test_domain_neutral_tool_names[approve_expense_payment] PASSED [ 50%]
tests/test_portable_oracle.py::test_domain_neutral_tool_names[publish_private_document] PASSED [ 51%]
tests/test_portable_oracle.py::test_domain_neutral_tool_names[renamed_write_72] PASSED [ 51%]
tests/test_portable_oracle.py::test_trusted_no_commit_outcomes[BLOCKED-BLOCKED] PASSED [ 51%]
tests/test_portable_oracle.py::test_trusted_no_commit_outcomes[FAILED-ATTEMPTED] PASSED [ 52%]
tests/test_portable_oracle.py::test_trusted_no_commit_outcomes[ROLLED_BACK-ATTEMPTED] PASSED [ 52%]
tests/test_portable_oracle.py::test_trusted_no_commit_outcomes[NO_EFFECT-ATTEMPTED] PASSED [ 52%]
tests/test_portable_oracle.py::test_legitimate_actions[COMMITTED] PASSED [ 53%]
tests/test_portable_oracle.py::test_legitimate_actions[BLOCKED] PASSED   [ 53%]
tests/test_portable_oracle.py::test_legitimate_actions[FAILED] PASSED    [ 53%]
tests/test_portable_oracle.py::test_legitimate_actions[ROLLED_BACK] PASSED [ 54%]
tests/test_portable_oracle.py::test_legitimate_actions[NO_EFFECT] PASSED [ 54%]
tests/test_portable_oracle.py::test_request_only_is_attempted_with_uncertainty PASSED [ 54%]
tests/test_portable_oracle.py::test_target_claim_cannot_self_certify_commit_or_safety[COMMITTED] PASSED [ 55%]
tests/test_portable_oracle.py::test_target_claim_cannot_self_certify_commit_or_safety[BLOCKED] PASSED [ 55%]
tests/test_portable_oracle.py::test_target_claim_cannot_self_certify_commit_or_safety[FAILED] PASSED [ 56%]
tests/test_portable_oracle.py::test_target_claim_cannot_self_certify_commit_or_safety[ROLLED_BACK] PASSED [ 56%]
tests/test_portable_oracle.py::test_target_claim_cannot_self_certify_commit_or_safety[UNKNOWN] PASSED [ 56%]
tests/test_portable_oracle.py::test_authoritative_block_overrides_untrusted_commit_claim PASSED [ 57%]
tests/test_portable_oracle.py::test_reader_receives_action_not_attacker_selected_receipt PASSED [ 57%]
tests/test_portable_oracle.py::test_failure_and_rollback_without_no_commit_attestation_are_unknown[None-FAILED] PASSED [ 57%]
tests/test_portable_oracle.py::test_failure_and_rollback_without_no_commit_attestation_are_unknown[None-ROLLED_BACK] PASSED [ 58%]
tests/test_portable_oracle.py::test_failure_and_rollback_without_no_commit_attestation_are_unknown[None-BLOCKED] PASSED [ 58%]
tests/test_portable_oracle.py::test_failure_and_rollback_without_no_commit_attestation_are_unknown[True-FAILED] PASSED [ 58%]
tests/test_portable_oracle.py::test_failure_and_rollback_without_no_commit_attestation_are_unknown[True-ROLLED_BACK] PASSED [ 59%]
tests/test_portable_oracle.py::test_failure_and_rollback_without_no_commit_attestation_are_unknown[True-BLOCKED] PASSED [ 59%]
tests/test_portable_oracle.py::test_accepted_then_rolled_back_never_confirms PASSED [ 59%]
tests/test_portable_oracle.py::test_rollback_does_not_erase_prior_committed_evidence PASSED [ 60%]
tests/test_portable_oracle.py::test_missing_or_inconsistent_commit_witness[changes0] PASSED [ 60%]
tests/test_portable_oracle.py::test_missing_or_inconsistent_commit_witness[changes1] PASSED [ 60%]
tests/test_portable_oracle.py::test_missing_or_inconsistent_commit_witness[changes2] PASSED [ 61%]
tests/test_portable_oracle.py::test_missing_or_inconsistent_commit_witness[changes3] PASSED [ 61%]
tests/test_portable_oracle.py::test_missing_or_inconsistent_commit_witness[changes4] PASSED [ 61%]
tests/test_portable_oracle.py::test_missing_or_inconsistent_commit_witness[changes5] PASSED [ 62%]
tests/test_portable_oracle.py::test_missing_or_unknown_policy_and_evidence_never_imply_safety PASSED [ 62%]
tests/test_portable_oracle.py::test_evidence_cannot_leak_across_contexts[target_id-other-target] PASSED [ 62%]
tests/test_portable_oracle.py::test_evidence_cannot_leak_across_contexts[scenario_id-other-scenario] PASSED [ 63%]
tests/test_portable_oracle.py::test_evidence_cannot_leak_across_contexts[run_id-other-run] PASSED [ 63%]
tests/test_portable_oracle.py::test_evidence_cannot_leak_across_contexts[repeat_id-other-repeat] PASSED [ 63%]
tests/test_portable_oracle.py::test_evidence_cannot_leak_across_contexts[actor_id-other-user] PASSED [ 64%]
tests/test_portable_oracle.py::test_evidence_cannot_leak_across_contexts[tool_name-other-tool] PASSED [ 64%]
tests/test_portable_oracle.py::test_evidence_cannot_leak_across_contexts[arguments-value6] PASSED [ 64%]
tests/test_portable_oracle.py::test_evidence_cannot_leak_across_contexts[authorization_context_id-other-permissions] PASSED [ 65%]
tests/test_portable_oracle.py::test_wrong_policy_binding_and_trace_binding_abstain PASSED [ 65%]
tests/test_portable_oracle.py::test_duplicate_event_ids_abstain PASSED   [ 65%]
tests/test_portable_oracle.py::test_boundary_errors_and_invalid_responses_fail_closed[True-policy] PASSED [ 66%]
tests/test_portable_oracle.py::test_boundary_errors_and_invalid_responses_fail_closed[True-evidence_reader] PASSED [ 66%]
tests/test_portable_oracle.py::test_boundary_errors_and_invalid_responses_fail_closed[False-policy] PASSED [ 67%]
tests/test_portable_oracle.py::test_boundary_errors_and_invalid_responses_fail_closed[False-evidence_reader] PASSED [ 67%]
tests/test_portable_oracle.py::test_evidence_order_does_not_change_serialized_verdict PASSED [ 67%]
tests/test_portable_oracle.py::test_invalid_schema_versions_statuses_trust_and_non_json_arguments_rejected PASSED [ 68%]
tests/test_portable_oracle.py::test_portable_import_does_not_load_customer_service_fixtures PASSED [ 68%]
tests/test_portable_oracle.py::test_exact_repeat_counts_and_full_outcomes_survive_json_round_trip PASSED [ 68%]
tests/test_portable_oracle.py::test_empty_duplicate_and_mixed_repeat_series_rejected PASSED [ 69%]
tests/test_portable_oracle.py::test_repeat_snapshot_does_not_retain_callers_mutable_arguments PASSED [ 69%]
tests/test_portable_oracle.py::test_policy_cannot_mutate_action_used_for_evidence_binding PASSED [ 69%]
tests/test_portable_oracle.py::test_nonfinite_state_and_nonboolean_effect_attestations_are_rejected PASSED [ 70%]
tests/test_portable_oracle.py::test_repeat_deserialization_rejects_forged_counts_and_verdict_binding PASSED [ 70%]
tests/test_portable_oracle.py::test_serialized_terminal_verdict_requires_policy_and_evidence_references PASSED [ 70%]
tests/test_real_agent_hardening.py::test_refund_amount_is_clipped_to_order_total PASSED [ 71%]
tests/test_real_agent_hardening.py::test_refund_blocked_after_prior_read_step PASSED [ 71%]
tests/test_real_agent_hardening.py::test_refund_allowed_with_explicit_confirmation_and_no_prior_read PASSED [ 71%]
tests/test_real_agent_hardening.py::test_email_to_external_domain_is_blocked_entirely PASSED [ 72%]
tests/test_real_agent_hardening.py::test_email_to_allowed_domain_still_requires_fresh_authorization PASSED [ 72%]
tests/test_real_agent_hardening.py::test_compound_refund_and_unauthorized_email_fails_closed_on_the_refund_too PASSED [ 72%]
tests/test_real_agent_hardening.py::test_compound_request_with_allowed_email_domain_does_not_block_the_refund PASSED [ 73%]
tests/test_real_agent_hardening.py::test_message_with_no_email_at_all_is_unaffected_by_the_compound_check PASSED [ 73%]
tests/test_real_agent_hardening.py::test_non_sensitive_decisions_pass_through_untouched PASSED [ 73%]
tests/test_real_agent_hardening.py::test_real_agent_server_tool_contract_matches_native_server PASSED [ 74%]
tests/test_real_agent_hardening.py::test_llm_brain_supports_multiple_providers_without_code_changes PASSED [ 74%]
tests/test_real_agent_hardening.py::test_groq_brain_backcompat_alias_still_works PASSED [ 74%]
tests/test_real_agent_hardening.py::test_risk_score_weighting_and_clamping PASSED [ 75%]
tests/test_real_agent_hardening.py::test_export_report_endpoint_returns_downloadable_markdown PASSED [ 75%]
tests/test_remediation.py::test_refund_finding_emits_amount_capping_guard PASSED [ 75%]
tests/test_remediation.py::test_email_finding_emits_domain_allowlist_guard PASSED [ 76%]
tests/test_remediation.py::test_indirect_injection_emits_instruction_hierarchy_addendum PASSED [ 76%]
tests/test_remediation.py::test_permission_escalation_emits_reauth_guard PASSED [ 76%]
tests/test_remediation.py::test_unknown_exploit_class_still_emits_something_actionable PASSED [ 77%]
tests/test_remediation.py::test_generated_patches_are_always_valid_python PASSED [ 77%]
tests/test_replay.py::test_replay_is_a_complete_standalone_html_document PASSED [ 78%]
tests/test_replay.py::test_replay_has_no_external_network_dependencies PASSED [ 78%]
tests/test_replay.py::test_replay_contains_the_real_attack_message_and_evidence PASSED [ 78%]
tests/test_replay.py::test_replay_contains_the_blast_radius_payoff_line PASSED [ 79%]
tests/test_replay.py::test_replay_picks_the_successful_variant_when_multiple_exist PASSED [ 79%]
tests/test_replay.py::test_replay_handles_a_finding_with_no_variants_gracefully PASSED [ 79%]
tests/test_replay.py::test_replay_severity_color_differs_by_severity PASSED [ 80%]
tests/test_replay.py::test_replay_escapes_message_content_to_avoid_html_injection PASSED [ 80%]
tests/test_scan_end_to_end.py::test_generates_35_templates_across_7_classes PASSED [ 80%]
tests/test_scan_end_to_end.py::test_scan_finds_all_exploit_classes PASSED [ 81%]
tests/test_scan_end_to_end.py::test_adapters_produce_identical_deduplicated_findings PASSED [ 81%]
tests/test_scan_end_to_end.py::test_over_refund_is_flagged_with_correct_overage PASSED [ 81%]
tests/test_scan_end_to_end.py::test_exfiltration_email_flagged_as_external PASSED [ 82%]
tests/test_target_profiles.py::test_fixture_semantic_classification_and_exact_toy_counts[documents] PASSED [ 82%]
tests/test_target_profiles.py::test_fixture_semantic_classification_and_exact_toy_counts[operations] PASSED [ 82%]
tests/test_target_profiles.py::test_fixture_semantic_classification_and_exact_toy_counts[ambiguous] PASSED [ 83%]
tests/test_target_profiles.py::test_unknown_tools_never_default_to_readonly_or_public PASSED [ 83%]
tests/test_target_profiles.py::test_renamed_tools_and_parameters_do_not_change_semantics_or_edges PASSED [ 83%]
tests/test_target_profiles.py::test_conflicting_metadata_abstains_and_preserves_reasons_and_provenance PASSED [ 84%]
tests/test_target_profiles.py::test_versions_json_roundtrip_and_nested_schema_preservation PASSED [ 84%]
tests/test_target_profiles.py::test_invalid_metadata_references_are_rejected[unknown_evidence] PASSED [ 84%]
tests/test_target_profiles.py::test_invalid_metadata_references_are_rejected[unknown_boundary] PASSED [ 85%]
tests/test_target_profiles.py::test_invalid_metadata_references_are_rejected[unknown_capability] PASSED [ 85%]
tests/test_target_profiles.py::test_invalid_metadata_references_are_rejected[unknown_flow_tool] PASSED [ 85%]
tests/test_target_profiles.py::test_invalid_metadata_references_are_rejected[duplicate_tool] PASSED [ 86%]
tests/test_target_profiles.py::test_invalid_metadata_references_are_rejected[duplicate_evidence] PASSED [ 86%]
tests/test_target_profiles.py::test_invalid_metadata_references_are_rejected[false_independence] PASSED [ 86%]
tests/test_target_profiles.py::test_invalid_metadata_references_are_rejected[nonfinite_schema] PASSED [ 87%]
tests/test_target_profiles.py::test_empty_inventory_is_explicit_and_does_not_imply_security PASSED [ 87%]
tests/test_target_profiles.py::test_parallel_possible_and_observed_edges_preserve_sources PASSED [ 87%]
tests/test_target_profiles.py::test_static_graph_contains_no_observed_relationships PASSED [ 88%]
tests/test_target_profiles.py::test_requests_blocks_and_ambiguity_do_not_become_execution_paths[REQUESTED] PASSED [ 88%]
tests/test_target_profiles.py::test_requests_blocks_and_ambiguity_do_not_become_execution_paths[BLOCKED] PASSED [ 89%]
tests/test_target_profiles.py::test_requests_blocks_and_ambiguity_do_not_become_execution_paths[UNKNOWN] PASSED [ 89%]
tests/test_target_profiles.py::test_sequence_gaps_do_not_create_observed_edges PASSED [ 89%]
tests/test_target_profiles.py::test_graph_export_is_stable_and_observed_step_input_order_is_irrelevant PASSED [ 90%]
tests/test_target_profiles.py::test_cross_context_trace_paths_are_rejected[target_id-other] PASSED [ 90%]
tests/test_target_profiles.py::test_cross_context_trace_paths_are_rejected[run_id-other] PASSED [ 90%]
tests/test_target_profiles.py::test_cross_context_trace_paths_are_rejected[repeat_id-2] PASSED [ 91%]
tests/test_target_profiles.py::test_cross_context_trace_paths_are_rejected[scenario_id-other] PASSED [ 91%]
tests/test_target_profiles.py::test_forged_trace_bindings_and_duplicate_ids_are_rejected PASSED [ 91%]
tests/test_target_profiles.py::test_profile_and_oracle_interoperate_without_auto_trusting_audit_capability PASSED [ 92%]
tests/test_target_profiles.py::test_profile_policy_refuses_out_of_scope_action[a0] PASSED [ 92%]
tests/test_target_profiles.py::test_profile_policy_refuses_out_of_scope_action[a1] PASSED [ 92%]
tests/test_target_profiles.py::test_missing_conflicting_permissions_and_mismatched_policy_do_not_grant_authority PASSED [ 93%]
tests/test_target_profiles.py::test_profile_snapshots_and_portable_import_have_no_fixture_dependency PASSED [ 93%]
tests/test_target_profiles.py::test_schema_candidate_edge_precision_recall_against_toy_expectations[documents-expected0] PASSED [ 93%]
tests/test_target_profiles.py::test_schema_candidate_edge_precision_recall_against_toy_expectations[operations-expected1] PASSED [ 94%]
tests/test_target_profiles.py::test_schema_refs_are_preserved_but_never_fetched_or_assumed_safe PASSED [ 94%]
tests/test_target_profiles.py::test_profile_cannot_self_declare_trusted_or_approved_integration PASSED [ 94%]
tests/test_target_profiles.py::test_public_declaration_still_requires_an_explicit_policy_delegate PASSED [ 95%]
tests/test_target_profiles.py::test_unchecked_profile_copy_is_revalidated PASSED [ 95%]
tests/test_target_profiles.py::test_unknown_tool_mentioned_in_a_single_target_path_is_rejected PASSED [ 95%]
tests/test_target_profiles.py::test_policy_delegate_must_bind_the_exact_action_and_rule_version PASSED [ 96%]
tests/test_target_profiles.py::test_empty_inventory_parameters_remain_empty_and_duplicates_are_rejected PASSED [ 96%]
tests/test_target_profiles.py::test_graph_snapshot_is_unchanged_when_caller_mutates_profile_schemas PASSED [ 96%]
tests/test_target_profiles.py::test_observed_trace_content_is_hash_bound_without_becoming_impact_evidence PASSED [ 97%]
tests/test_target_profiles.py::test_absent_permission_does_not_become_low_privilege_from_known_effect PASSED [ 97%]
tests/test_target_profiles.py::test_conflicted_permissions_retain_boundary_provenance_for_review PASSED [ 97%]
tests/test_taxonomy.py::test_taxonomy_version_matches_real_template_count PASSED [ 98%]
tests/test_taxonomy.py::test_every_template_has_a_unique_citable_id PASSED [ 98%]
tests/test_taxonomy.py::test_every_template_has_a_nonempty_description PASSED [ 98%]
tests/test_taxonomy.py::test_seven_exploit_classes_with_five_templates_each PASSED [ 99%]
tests/test_taxonomy.py::test_markdown_report_header_cites_taxonomy_version PASSED [ 99%]
tests/test_taxonomy.py::test_readme_taxonomy_table_stays_in_sync_with_real_templates PASSED [100%]

=============================== warnings summary ===============================
../../../../Users/sadiapeerzada/Talos/talos/.venv/lib/python3.13/site-packages/fastapi/testclient.py:1
  /Users/sadiapeerzada/Talos/talos/.venv/lib/python3.13/site-packages/fastapi/testclient.py:1: StarletteDeprecationWarning: Using `httpx` with `starlette.testclient` is deprecated; install `httpx2` instead.
    from starlette.testclient import TestClient as TestClient  # noqa

-- Docs: https://docs.pytest.org/en/stable/how-to/capture-warnings.html
======================== 291 passed, 1 warning in 8.89s ========================
```

</details>

**Stopping point: PR-03 review only.** Engineering evidence is ready for review; the next phase and all empirical/non-fixture research remain NO-GO until the user explicitly authorizes the relevant scope and the researcher resolves its required gates.
