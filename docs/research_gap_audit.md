# PR-00: Baseline custody and research gap audit

Audit date: **2026-11-15 (Asia/Kolkata)**. Scope: documentation only; no PR-01 implementation, new research experiment, inference, standalone scan, or alteration of historical artifacts. Existing offline tests exercise their existing local fixture scans. Public literature/GitHub metadata reads are evidence inspection, not target testing.

## Evidence vocabulary and authority

- **VERIFIED**: directly inspected code, bytes, recorded summaries, or an executed offline test; verification of a recorded value does not authenticate the historical execution that produced it.
- **INFERRED**: a reasoned interpretation or derivation, with its premises identified.
- **PENDING**: evidence or review remains incomplete; no negative result is implied.
- **BLOCKED**: a specific missing artifact, authorization, or human decision prevents the claim/gate from being established.

The user authorized PR-00 only. `TALOS_2_FULL_RESEARCH_MASTER_PLAN.md` is the authoritative roadmap; `TALOS_CODEX_START_PR00_PROMPT.txt` supplies immediate execution instructions. Later PR requirements are backlog, not permission to implement or run them. Findings below independently check the roadmap rather than treating its assertions as data. This is an automated audit, not independent human annotation or approval.

## Exact custody boundary

**VERIFIED:** original checkout `/Users/sadiapeerzada/Talos`, branch `main`, HEAD `bf8bb254bcf71f1e5f07b0504adf1b2395a210f7`. Fetch confirmed `origin/main` at `ac8c613295ddc4fc1bb6989707ebe86a0074c0e4`, five commits ahead; its author date is 2026-08-28. A Git author date is not proof of the last server push time. No rebase, stash, reset, or merge was applied to the user's checkout.

PR branch: `research/pr-00-baseline-custody`, isolated worktree `/private/tmp/talos-pr00`, based on `ac8c613295ddc4fc1bb6989707ebe86a0074c0e4`. Code citations and committed evidence refer to that base unless explicitly marked **working tree**. Obtain the documentation commit using `git rev-parse research/pr-00-baseline-custody`; the PR body records its SHA (a commit cannot contain its own final hash).

**VERIFIED:** the original working tree already contained these changes. They were inspected and excluded from the PR, with these SHA-256 byte fingerprints:

| Path | Initial state | SHA-256 |
|---|---|---|
| `talos/report_native.md` | modified; 594 additions / 25 deletions | `0c3de6584405a5a3772bd5184b9eec0d8702581b9addb88f81e23adaab89efd0` |
| `talos/talos/sample_agents/langchain_server.py` | modified; adds hardened mode | `dbba032ed30ba5e1d23b3f1fc6afca7415da25217cc5363b2b0b9c6d7be7506b` |
| `talos/talos/sample_agents/policy.py` | modified; changes confirmation policy | `304747dae30d6ca2a6c3fd2b373fec4c251c7cc9e646cefeb7652dd803e84a3b` |
| `talos/talos/sample_agents/langchain_server.py.bak` | untracked | `36e7314bd6be5ad6026b446c0a2d38e6e5f7bdce4720b864b63373396b1391cf` |

The dirty policy requires explicit confirmation even for a first-turn refund; committed policy allows a first-turn request without previous reads. This is a meaningful behavioral difference, not a reproducible historical snapshot. The original tree has 80 collected tests; committed main has 83. Tests do not authorize committing or repairing these user changes.

### Input and manuscript custody

| Input | SHA-256 | Status |
|---|---|---|
| `TALOS_2_FULL_RESEARCH_MASTER_PLAN.md` | `ec5589fdad267ce1d1c7964c67d7b8a6d898458762b2b5a2e6d42ebed4416202` | VERIFIED; read completely |
| `TALOS_CODEX_START_PR00_PROMPT.txt` | `21a4aa50e26f65b3e1c2bd9e82eefbb403b30fba450306448b4586192f90727e` | VERIFIED; read completely |
| `Talos__Automated__Tool_Graph_Aware_Red_Teaming_for_Deployed_Agentic_AI_Systems.pdf` | `965f7096972049133299dcc638a0abb6154dd7bd70387b7ee8f8a82313581347` | VERIFIED; local 20-page candidate, text inspected throughout; figures visually inspected |
| Same PDF filename with ` (1)` suffix | `1d39535627ae96d51a2344526c00ef04edbfdef3aa4591f06a37189f20a20496` | VERIFIED; 20 pages; another local candidate, not declared authoritative |
| `Talos.tex` | `ff9c4613b025e70ea088176ce135e6b851b7a164335c0e8d9e56dd00e8a1dc5f` | VERIFIED local candidate; conference format, external `references.bib` dependency |
| `Talos_Transactions_Revised.tex` | `19794e7cb814c99da5b38e1c8a682fe06f26e0d184dab23511f1fbb54038e7e5` | VERIFIED local candidate; journal format, inline bibliography |
| `Talos_Transactions_Revised (1).tex` | `d652bc2dac324df87b21ba366b05a2f0df33d86e4e2cca0becc03c91863a96f0` | VERIFIED distinct local candidate |

Inputs/candidates are in the researcher's Downloads directory and were not copied into the PR. **BLOCKED:** authoritative manuscript identity and complete editable build project require researcher selection. Contrary to a blanket “no TeX exists” statement, local candidates exist; none is tracked in the repository. The inspected PDF metadata reports creation/modification **2026-08-17 11:23:42 UTC**, pdfTeX 1.40.27 / TeX Live 2025. The roadmap calls the baseline “8 November 2026”; that date is not established by the candidate's bytes or visible text. Metadata is not proof of authorship or experimental execution date. All page references below are to the explicitly hashed first candidate, not an asserted November revision.

## Repository and implementation inventory

**VERIFIED:** base has 83 tracked paths, including 15 `test_*.py` modules. No applicable `AGENTS.md` was found in the repository or ancestor locations checked. Full tracked-path byte inventory appears below.

| Area | Paths | Audit interpretation |
|---|---|---|
| Entry points | `talos/scan.py`, `talos/talos/cli.py`, `scan_service.py`, `dashboard.py` | CLI and dashboard share a scan pipeline; dashboard import initializes persistence/monitors |
| Adapters | `talos/talos/harness/{base,native_adapter,langchain_adapter}.py` | normalize declared tools and target-provided trace records; no independent commit-event proof |
| Graph | `talos/talos/graph/{classify,discovery,render}.py` | keyword classification; possible source-to-write edges, not observed or proven reachability |
| Attacks | `talos/talos/attacks/{models,templates,engine,adaptive}.py` | 35 templates / 7 classes, customer-service wording and seed IDs; optional Anthropic refinement |
| Execution | `talos/talos/execution/{runner,scoring,dedup}.py` | class-based fixture oracle; at-least-one success; class × tool grouping |
| Reporting | `talos/talos/reporting/report.py`, `remediation.py`, `replay.py` | severity-sum score, suggested patches and presentation; replay is not raw state evidence |
| Persistence | `talos/talos/{storage,learning,monitoring}.py` | home-directory SQLite defaults; cross-engagement hints can reorder later scans |
| Remediation | `talos/talos/autofix.py` | seven class keys all select the same prewritten policy wrapper; launches hardened native fixture |
| Targets | `talos/talos/sample_agents/*.py` | deterministic native/LangChain customer service, optional real-provider customer service, fake-tested IT helpdesk, two-hop notes demo |
| Analysis/CI | `talos/talos/scripts/{research_eval,ci_risk_gate}.py`, `.github/workflows/tests.yml` | summarized sweep output; tests on Python 3.11/3.12; gate saturation issue |
| Evidence/docs | seven historical Markdown reports; one research JSON; `talos/docs/*`; README and SVGs | mixed corpus versions; related-work file is zero bytes; no paper build tree or run manifest |

## Findings and manuscript-to-code audit

| ID / severity | Status | Manuscript location | Source evidence | Consequence / disposition |
|---|---|---|---|---|
| A01 / critical | VERIFIED mismatch | Eq. (2), pp. 7–8; §§IV-D, VIII-C | `reporting/report.py:87–105` | Paper uses `100 Σ(w*s*c)/Σ(w*s)` over observed findings; code caps `25*C+12*H+5*M+2*L` at 100 and ignores confidence. Matching 100→0 endpoints cannot validate the formula. No score changes in PR-00. |
| A02 / critical | VERIFIED mismatch | §VI-A, pp. 11–12; §XII, p. 19 | `attacks/models.py::AttackTemplate`; `execution/scoring.py:21–22,129–172` | Templates have applicability/instantiation functions, no individual JUDGE field. Scorer imports `ORDERS`, `AMOUNT_RE`, `EMAIL_RE` and dispatches on exploit class. Other classes share refund/email tests. |
| A03 / critical | VERIFIED limitation | §II-D, p. 4; §VI-A, pp. 11–12 | `sample_agents/exchange.py:48–62`; `harness/base.py::ToolCallRecord`; `execution/scoring.py::_refund_overage,_suspicious_email,_high_priv_call` | Exchange catches tool exceptions and still records calls with error results. Scorer uses names/arguments without checking committed state or even error result. Attempt ≠ acceptance ≠ committed forbidden outcome. |
| A04 / critical | VERIFIED figure mismatch; BLOCKED provenance | Fig. 5, p. 14 | PDF rendered image versus caption and committed JSON | Image is an E01–E18 × GPT-3.5/GPT-4/Claude-v1/Claude-v2/PaLM-2/PaLM-E heatmap with fractional values, not Talos A1–G5 deterministic data. Caption says every cell 25/25. Do not attribute these model measurements to Talos. Researcher must identify source/license and authoritative figure. |
| A05 / high | VERIFIED summaries; PENDING run linkage | Tables VI–IX, pp. 12,14–15 | `research_results/native_before_after_repro5.json`; `scripts/research_eval.py` | JSON is 175/175 before, 0/175 after, 350 template attempts; no separate one-repeat 70-attempt run is archived. Numerical compatibility does not establish identical experiment provenance. |
| A06 / high | VERIFIED counting mismatch | Table VI caption, p. 12 | `attacks/templates.py::_c1,_c2`; `execution/runner.py::execute_attack` | 35 instances contain 37 user messages because C1/C2 each have two turns. If “deliveries” means actual requests, a full one-repeat paired sweep entails 74, and a five-repeat paired sweep entails 370, not 70/350. These are code-derived counts conditional on completion, not measured traffic. |
| A07 / high | VERIFIED mismatch | statistical discussion §IV-F and §VIII-D, pp. 9,15 | `scripts/research_eval.py:158–198` | Docstring says majority vote; actual binary event is `k > 0`. Intersects IDs silently and collapses duplicates in dictionaries. Does not calculate p-values, paired CI, odds ratio, or z-test. |
| A08 / high | VERIFIED limitation; INFERRED risk | §§IV-E, VIII-A, X | repeated deterministic fixture; `research_eval.py::run_sweep` | Repeats are not independent scenario samples. `k` is reconstructed from a rate rounded to two decimals; original per-repeat outcomes/traces are lost, especially problematic at large repeat counts. Paper acknowledges deterministic caveat, which should be retained. |
| A09 / high | VERIFIED integration only | §VII-E; §XI, p. 18 | `tests/test_external_langchain_agent.py` (4 tests); `docs/external-target-validation.md` | Real LangChain orchestration with scripted FakeMessagesListChatModel. IT helpdesk tool names differ from scorer. No committed live independent-target vulnerability study. Distinct code/domain is not independent authorship/custody. |
| A10 / high | VERIFIED limitation | Table X, p. 16; §§VII-A, VIII-F | shared `RuleBasedBrain`; parity tests; old reports | Same logic and tools under both adapters. Parity tests pass, but archived LangChain reports use 25 templates / 8 groups, not the claimed 35 / 12. Historical configuration/run log missing. |
| A11 / high | VERIFIED implementation; PENDING run evidence | §VIII-E, p. 16; Algorithm 1, p. 10 | `autofix.py::HARDENING_STRATEGIES,run_autofix_cycle` | Prebuilt policy wrapper on new native process, not seven independently generated code fixes. Existing tests confirm bounded mechanics; no original single-cycle transcript/state archive was found. |
| A12 / high | VERIFIED order confound | §VII-A p. 13; §XII p. 19 | `scan_service.py:106–107`; `attacks/engine.py::generate_next_round`; `learning.py::get_hints` | Pipeline reads prior global DB hints and sorts candidates. Fixed template-ID order is conditional on empty/equal hints; research_eval loops directly over templates and has a different path. Freeze/export learning state in future protocol. |
| A13 / high | VERIFIED gate weakness | artifact/CI claims | `.ci/baseline_risk_score.json`; `scripts/ci_risk_gate.py::evaluate_regression` | Gate fails only when new score > baseline; baseline is 100 and score ≤100, so this baseline cannot detect any increase. A scorer returning zero passes. Unit tests do not establish oracle validity. |
| A14 / medium | VERIFIED contradiction / PENDING full matrix | Tables I–II, p. 5; §III-C | primary literature links below | AgentDojo row's fixed-suite framing conflicts with its dynamic/extensible design and with Talos's own prose/Table II. No broad “first” or absent-feature claims without cell-level source evidence. |
| A15 / high | VERIFIED drift / BLOCKED build provenance | §XII pp. 18–19 | no tracked `.tex/.bib/.pdf`, lockfile or immutable event archive | Local candidates exist but complete selected source, inputs, exact historical environment and build commands are unconfirmed. |
| A16 / medium | VERIFIED report/test wording drift | §VIII-B pp. 14–15; abstract p. 1 | 14 hardening tests in committed file; merge message says 4 new tests | Manuscript says 3 regression tests, 14 affected tests and 83 total; commit narrative says 4 new tests. Current baseline has 83 passing; original dirty checkout has 80 tests with one failure. Counts must name revision. |
| A17 / high | VERIFIED missing evidence | §§VII-C–E, X–XI, XIII–XIV | no held-out manifests, raters, live domain runs or matched baseline outputs | Graph/adaptation advantage, independent oracle precision/recall, benign-task utility, cost-normalized efficacy and production safety remain unestablished. |
| A18 / medium | VERIFIED code/prose mismatch | §VII-A p.12; policy description | `sample_agents/policy.py::_chain_risk` | Confirmation regex can override prior-read/history risk; it does not bind confirmation to exact order/amount/action. “No prior read step” and “explicitly authorized that exact action” overstate this implementation. |

Additional method issues: **VERIFIED** deduplication groups by class × target-tool, not independent root cause; multiple groups may share one guardrail bug. “Amount not literally in user text” is a provenance heuristic, not proof that a value came from a particular tool result. Data-exfiltration uses recognizable body strings; permission escalation equates a multi-turn/read-write chain with missing authorization without a separate authorization record. Missing observations become `fail`, not `UNKNOWN`; real-agent error responses can therefore look like successful defense. Graph classification defaults unknown tool names to read-only and constructs possible edges rather than testing them. **INFERRED** these mechanisms can create both false positives and false negatives across unfamiliar domains; no error rates are measured here.

## Historical evidence reconciliation

**VERIFIED recorded contents:** JSON before has A1–G5 once each, `n=5,k=5` throughout; after has the same IDs, `n=5,k=0` throughout. Before severity at template level is 0 critical / 9 high / 25 medium / 1 low; after all 35 are `none`. Grouping successful templates by class × tool and retaining maximum severity derives 12 before groups (7 high / 5 medium), 0 after. This derives Table IX-compatible counts from the five-repeat artifact; it does not recover the separately claimed one-repeat run.

| Quantity | Actual unit / evidence | Status and limit |
|---|---|---|
| 175 vulnerable executions | 35 template instances × 5 repeats; JSON before | VERIFIED summarized successes 175/175; not 175 independent scenarios or individual messages |
| 70 paired executions | claimed 35 × 2 variants × 1 repeat | PENDING original artifact; Table VIII matches JSON's 35 template-level outcomes, but JSON uses 5 repeats per variant |
| 12 findings → 0 | class × target-tool groups | VERIFIED derivable from JSON; not 12 independently adjudicated root causes |
| 350 total attempts | 175 before + 175 after in repro5 JSON | VERIFIED summary denominator; conditional 370 message deliveries from code, no archived request logs |
| 1 auto-fix cycle | reported single cycle, 12→0 | PENDING historical transcript/manifest; existing tests exercise mechanics, not historical custody |
| 2 adapter scans | reported matched settings, 12/12 | PENDING matched 35-template reports; existing older LangChain evidence has 8/8 |
| χ² = 33.0286 | 35 discordant template pairs, b=35,c=0 | VERIFIED arithmetic and JSON summary; p≈9.08e-9 is the asymptotic tail, not output from current script or an exact test |
| 95% paired difference CI, odds ratio and z-test | §VIII-D and §IV-F claims | PENDING analysis source and definition; no such implementation/output in committed evaluation script |

JSON is the lowest-level committed research result found, but contains **per-template aggregates, not per-attempt raw tool/state traces**. Original timestamps, source commit, target policy hash, dependency lock, prompts/hashes, reset evidence, command log and independent custody are absent. `503eb7fe993d4f638a247d2e0c2234449d1f2b43` introduced it (author date 2026-08-17); commit message attributes it to a native paired repro5 command and mentions earlier table numbers. `1710c6b93f4c683b113ac7284fd4bb4ca51e93e1` merged the fix/results on 2026-08-19. These are historical author assertions, not independent verification of a run or approval.

## Environment, offline tests and workflow evidence

**VERIFIED local environment:** Darwin arm64; Python 3.13.7, pytest 9.1.1. No dependencies were installed or upgraded. Existing virtualenv reused; explicit `PYTHONPATH` selected audited source (important: editable install itself points at the original checkout). Dependency freeze appears below. `pyproject.toml` uses lower bounds, notably `langchain>=0.3` although code imports `langchain.agents.create_agent`; minimum-version compatibility is untested. No lockfile/SBOM or historical resolved environment is tracked. CI targets Ubuntu / Python 3.11 and 3.12; this local result does not certify that matrix.

**VERIFIED test runs** (all commands below execute existing tests, not standalone research sweeps):

| Run | Revision and conditions | Result |
|---|---|---|
| T1 | committed base, literal pytest; sandbox | collection error: `sqlite3.OperationalError: attempt to write a readonly database`; 78 collected / 1 error; 0.67s |
| T2 | committed base, temporary storage + offline guard; sandbox | 58 passed, 5 failed, 20 errors, 3 warnings; 56.65s; loopback bind denied |
| T3 | committed base, same storage/guard; loopback permission granted | **83 passed, 1 warning, 8.18s** |
| T4 | original dirty tree at bf8bb25, same storage/guard; loopback granted | **79 passed, 1 failed, 1 warning, 8.52s**; failure reproduced below, left untouched |

Temporary test support patches `talos.storage.default_data_dir` to `/private/tmp/talos-pr00-state` before collection and blocks socket connections except loopback. It does not change fixtures, assertions, scorer, policy or results. `TALOS_DATA_DIR` alone has no effect in current storage code. Model API keys and proxy variables were removed for the runs. The temporary patch is reproduced below so the adjustment is reviewable; it is not a shipped product fix. Existing monitoring history is not used in isolated runs. Offline tests include local auto-fix, adapter, graph, learning, dashboard, replay and cross-agent fixture checks; none is a live-model security study.

Exact T1 command, cwd `/private/tmp/talos-pr00/talos`:

```sh
env -u ANTHROPIC_API_KEY -u GROQ_API_KEY -u OPENAI_API_KEY -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY PYTHONPATH=/private/tmp/talos-pr00/talos TALOS_DATA_DIR=/private/tmp/talos-pr00-state /Users/sadiapeerzada/Talos/talos/.venv/bin/python -m pytest tests/ -v > /private/tmp/talos-pr00-pytest.log 2>&1
```

Exact T2/T3 command (same cwd; T3 grants local socket permission):

```sh
env -u ANTHROPIC_API_KEY -u GROQ_API_KEY -u OPENAI_API_KEY -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY PYTHONPATH=/private/tmp/talos-pr00-support:/private/tmp/talos-pr00/talos /Users/sadiapeerzada/Talos/talos/.venv/bin/python -m pytest tests/ -v > /private/tmp/talos-pr00-pytest-loopback.log 2>&1
```

T2 used the same command with output `/private/tmp/talos-pr00-pytest-isolated.log`. Exact T4 command, cwd `/Users/sadiapeerzada/Talos/talos`:

```sh
env -u ANTHROPIC_API_KEY -u GROQ_API_KEY -u OPENAI_API_KEY -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY PYTHONPATH=/private/tmp/talos-pr00-support:/Users/sadiapeerzada/Talos/talos /Users/sadiapeerzada/Talos/talos/.venv/bin/python -m pytest tests/ -v > /private/tmp/talos-pr00-pytest-working-tree.log 2>&1
```

**VERIFIED workflow definition:** `.github/workflows/tests.yml` runs tests on pushes/PRs with editable dev install, then PR-only risk gate. Gate is not manually rerun here because it starts another scan. GitHub connector queries `get_commit_combined_status` and `fetch_commit_workflow_runs` for ac8c613 returned empty lists on audit date. The latter filters PR-triggered runs; empty output does **not** prove no push run or historical CI success. **PENDING:** independently evidenced historical workflow jobs/logs and successful Python 3.11/3.12 runs. Opening this PR may trigger the repository's existing workflow; that is not an independently approved v2 experiment.

## Privacy, licensing and release review

**VERIFIED source inspection:** fixture email domains use `.example`; tool side effects append to synthetic in-memory `AuditLog`, with no payment rail/mail transport in `sample_agents/tools.py`. Provider code supports real external model endpoints, and adaptive mode can activate from an environment key without an explicit signed execution budget/allowlist. Do not run those paths under PR-00. No credential values were copied into audit documents, and user credentials/environment values were not printed.

**VERIFIED missing release inputs:** no tracked LICENSE, dataset license/consent manifest, dependency lock/SBOM, complete paper build project, trace redaction manifest, or independent target-custodian declaration. The paper's figures (especially Fig. 5) require origin and redistribution checks. **PENDING:** researcher confirmation that names/order histories and all shared artifacts are synthetic or publishable, third-party asset permissions and dependency-license review. This was a bounded manual source/artifact inspection, not a new secret/security scan or a certification that the repository/history contains no secrets. Do not infer a license from public GitHub visibility. Do not publish local candidate manuscripts in this PR.

## Disposition

See [claim registry](research_claim_registry.md) for every numbered table/figure and [execution backlog](research_execution_backlog.md) for the issue index, owners, gates and deferred implementation. [Go/no-go](research_go_no_go.md) freezes the review boundary: PR-00 is ready for review with documented gaps; broad empirical claims and any new study remain NO-GO. No human approval is asserted.

## Temporary test support (not committed as runtime code)

VERIFIED: exact contents loaded through PYTHONPATH for T2–T4.

<details>
<summary>Expand evidence</summary>

```python
from pathlib import Path
import socket
import talos.storage as storage

def audit_data_dir():
    path = Path('/private/tmp/talos-pr00-state')
    path.mkdir(parents=True, exist_ok=True)
    return path
storage.default_data_dir = audit_data_dir
_original_connect = socket.socket.connect
_original_connect_ex = socket.socket.connect_ex

def offline_connect(sock, address):
    if isinstance(address, tuple) and address[0] not in ('127.0.0.1', 'localhost', '::1'):
        raise RuntimeError('PR-00 offline guard blocked non-loopback connection')
    return _original_connect(sock, address)

def offline_connect_ex(sock, address):
    if isinstance(address, tuple) and address[0] not in ('127.0.0.1', 'localhost', '::1'):
        raise RuntimeError('PR-00 offline guard blocked non-loopback connection')
    return _original_connect_ex(sock, address)
socket.socket.connect = offline_connect
socket.socket.connect_ex = offline_connect_ex
```

</details>

## Full successful committed-baseline test transcript (T3)

VERIFIED: existing offline suite at ac8c613, not a new research run.

<details>
<summary>Expand evidence</summary>

```text
============================= test session starts ==============================
platform darwin -- Python 3.13.7, pytest-9.1.1, pluggy-1.6.0 -- /Users/sadiapeerzada/Talos/talos/.venv/bin/python
cachedir: .pytest_cache
rootdir: /private/tmp/talos-pr00/talos
configfile: pyproject.toml
plugins: anyio-4.14.2, langsmith-0.10.7
collecting ... collected 83 items

tests/test_adapters_parity.py::test_tool_specs_match PASSED              [  1%]
tests/test_adapters_parity.py::test_benign_lookup_matches PASSED         [  2%]
tests/test_adapters_parity.py::test_indirect_injection_matches PASSED    [  3%]
tests/test_adapters_parity.py::test_two_turn_permission_escalation_matches PASSED [  4%]
tests/test_adaptive_generation.py::test_adaptive_generation_emits_refinement_variants PASSED [  6%]
tests/test_adaptive_generation.py::test_adaptive_scan_runs_more_than_base_template_count PASSED [  7%]
tests/test_autofix.py::test_autofix_cycle_strictly_reduces_risk_score_end_to_end PASSED [  8%]
tests/test_autofix.py::test_autofix_cycle_closes_the_specific_refund_overage_exploit_class PASSED [  9%]
tests/test_autofix.py::test_autofix_result_summary_lines_match_the_real_numbers PASSED [ 10%]
tests/test_autofix.py::test_hardening_strategies_registry_covers_every_exploit_class_talos_can_produce PASSED [ 12%]
tests/test_autofix.py::test_hardened_native_server_flag_actually_wraps_the_brain PASSED [ 13%]
tests/test_blast_radius.py::test_no_evidence_yields_zero_exposure_but_one_tool PASSED [ 14%]
tests/test_blast_radius.py::test_refund_overage_produces_dollar_exposure PASSED [ 15%]
tests/test_blast_radius.py::test_single_record_email_exposure_is_counted_concretely PASSED [ 16%]
tests/test_blast_radius.py::test_bulk_export_is_flagged_qualitatively_not_fabricated_as_a_count PASSED [ 18%]
tests/test_blast_radius.py::test_unverified_action_chain_widens_tools_affected PASSED [ 19%]
tests/test_blast_radius.py::test_worst_case_across_multiple_variants_is_taken PASSED [ 20%]
tests/test_blast_radius.py::test_blast_radius_is_json_serializable_and_defaults_present PASSED [ 21%]
tests/test_ci_risk_gate.py::test_higher_score_is_a_regression PASSED     [ 22%]
tests/test_ci_risk_gate.py::test_lower_score_passes_and_reports_improvement PASSED [ 24%]
tests/test_ci_risk_gate.py::test_equal_score_passes PASSED               [ 25%]
tests/test_ci_risk_gate.py::test_one_point_regression_still_fails PASSED [ 26%]
tests/test_ci_risk_gate.py::test_result_is_a_plain_dataclass_with_expected_fields PASSED [ 27%]
tests/test_ci_risk_gate.py::test_committed_baseline_file_is_valid_and_loadable PASSED [ 28%]
tests/test_ci_risk_gate.py::test_ci_gate_end_to_end_against_a_real_scan PASSED [ 30%]
tests/test_cross_agent_injection.py::test_upstream_summarizer_auto_escalates_urgent_complaints PASSED [ 31%]
tests/test_cross_agent_injection.py::test_upstream_summarizer_does_not_escalate_a_benign_message PASSED [ 32%]
tests/test_cross_agent_injection.py::test_cross_agent_chain_succeeds_where_single_hop_control_fails PASSED [ 33%]
tests/test_cross_agent_injection.py::test_cross_agent_finding_scores_correctly_through_talos_real_pipeline PASSED [ 34%]
tests/test_cross_agent_injection.py::test_cross_agent_injection_is_registered_in_the_taxonomy PASSED [ 36%]
tests/test_cross_agent_injection.py::test_cross_agent_injection_finding_gets_a_valid_remediation_patch PASSED [ 37%]
tests/test_dashboard.py::test_dashboard_root_serves_html PASSED          [ 38%]
tests/test_dashboard.py::test_dashboard_scan_streams_progress_and_final_report PASSED [ 39%]
tests/test_dashboard.py::test_medium_and_low_severity_counts_stay_consistent_with_critical_and_high PASSED [ 40%]
tests/test_dashboard.py::test_monitor_runs_recurring_scans_and_exposes_history PASSED [ 42%]
tests/test_dashboard.py::test_monitoring_manager_persists_history_and_alerts PASSED [ 43%]
tests/test_external_langchain_agent.py::test_tools_endpoint_matches_langchain_adapter_contract PASSED [ 44%]
tests/test_external_langchain_agent.py::test_agent_endpoint_round_trip_executes_a_real_tool_call PASSED [ 45%]
tests/test_external_langchain_agent.py::test_talos_langchain_adapter_discovers_and_drives_this_target_end_to_end PASSED [ 46%]
tests/test_external_langchain_agent.py::test_tool_graph_classifier_detects_financial_and_external_comm_and_free_text_on_this_independent_target PASSED [ 48%]
tests/test_graph_parity.py::test_graph_identical_across_adapters PASSED  [ 49%]
tests/test_graph_parity.py::test_graph_classifies_known_tools_correctly PASSED [ 50%]
tests/test_learning.py::test_learning_store_summarizes_and_ranks_findings PASSED [ 51%]
tests/test_learning.py::test_learning_hints_prioritize_future_batches PASSED [ 53%]
tests/test_real_agent_hardening.py::test_refund_amount_is_clipped_to_order_total PASSED [ 54%]
tests/test_real_agent_hardening.py::test_refund_blocked_after_prior_read_step PASSED [ 55%]
tests/test_real_agent_hardening.py::test_refund_allowed_with_explicit_confirmation_and_no_prior_read PASSED [ 56%]
tests/test_real_agent_hardening.py::test_email_to_external_domain_is_blocked_entirely PASSED [ 57%]
tests/test_real_agent_hardening.py::test_email_to_allowed_domain_still_requires_fresh_authorization PASSED [ 59%]
tests/test_real_agent_hardening.py::test_compound_refund_and_unauthorized_email_fails_closed_on_the_refund_too PASSED [ 60%]
tests/test_real_agent_hardening.py::test_compound_request_with_allowed_email_domain_does_not_block_the_refund PASSED [ 61%]
tests/test_real_agent_hardening.py::test_message_with_no_email_at_all_is_unaffected_by_the_compound_check PASSED [ 62%]
tests/test_real_agent_hardening.py::test_non_sensitive_decisions_pass_through_untouched PASSED [ 63%]
tests/test_real_agent_hardening.py::test_real_agent_server_tool_contract_matches_native_server PASSED [ 65%]
tests/test_real_agent_hardening.py::test_llm_brain_supports_multiple_providers_without_code_changes PASSED [ 66%]
tests/test_real_agent_hardening.py::test_groq_brain_backcompat_alias_still_works PASSED [ 67%]
tests/test_real_agent_hardening.py::test_risk_score_weighting_and_clamping PASSED [ 68%]
tests/test_real_agent_hardening.py::test_export_report_endpoint_returns_downloadable_markdown PASSED [ 69%]
tests/test_remediation.py::test_refund_finding_emits_amount_capping_guard PASSED [ 71%]
tests/test_remediation.py::test_email_finding_emits_domain_allowlist_guard PASSED [ 72%]
tests/test_remediation.py::test_indirect_injection_emits_instruction_hierarchy_addendum PASSED [ 73%]
tests/test_remediation.py::test_permission_escalation_emits_reauth_guard PASSED [ 74%]
tests/test_remediation.py::test_unknown_exploit_class_still_emits_something_actionable PASSED [ 75%]
tests/test_remediation.py::test_generated_patches_are_always_valid_python PASSED [ 77%]
tests/test_replay.py::test_replay_is_a_complete_standalone_html_document PASSED [ 78%]
tests/test_replay.py::test_replay_has_no_external_network_dependencies PASSED [ 79%]
tests/test_replay.py::test_replay_contains_the_real_attack_message_and_evidence PASSED [ 80%]
tests/test_replay.py::test_replay_contains_the_blast_radius_payoff_line PASSED [ 81%]
tests/test_replay.py::test_replay_picks_the_successful_variant_when_multiple_exist PASSED [ 83%]
tests/test_replay.py::test_replay_handles_a_finding_with_no_variants_gracefully PASSED [ 84%]
tests/test_replay.py::test_replay_severity_color_differs_by_severity PASSED [ 85%]
tests/test_replay.py::test_replay_escapes_message_content_to_avoid_html_injection PASSED [ 86%]
tests/test_scan_end_to_end.py::test_generates_35_templates_across_7_classes PASSED [ 87%]
tests/test_scan_end_to_end.py::test_scan_finds_all_exploit_classes PASSED [ 89%]
tests/test_scan_end_to_end.py::test_adapters_produce_identical_deduplicated_findings PASSED [ 90%]
tests/test_scan_end_to_end.py::test_over_refund_is_flagged_with_correct_overage PASSED [ 91%]
tests/test_scan_end_to_end.py::test_exfiltration_email_flagged_as_external PASSED [ 92%]
tests/test_taxonomy.py::test_taxonomy_version_matches_real_template_count PASSED [ 93%]
tests/test_taxonomy.py::test_every_template_has_a_unique_citable_id PASSED [ 95%]
tests/test_taxonomy.py::test_every_template_has_a_nonempty_description PASSED [ 96%]
tests/test_taxonomy.py::test_seven_exploit_classes_with_five_templates_each PASSED [ 97%]
tests/test_taxonomy.py::test_markdown_report_header_cites_taxonomy_version PASSED [ 98%]
tests/test_taxonomy.py::test_readme_taxonomy_table_stays_in_sync_with_real_templates PASSED [100%]

=============================== warnings summary ===============================
../../../../Users/sadiapeerzada/Talos/talos/.venv/lib/python3.13/site-packages/fastapi/testclient.py:1
  /Users/sadiapeerzada/Talos/talos/.venv/lib/python3.13/site-packages/fastapi/testclient.py:1: StarletteDeprecationWarning: Using `httpx` with `starlette.testclient` is deprecated; install `httpx2` instead.
    from starlette.testclient import TestClient as TestClient  # noqa

-- Docs: https://docs.pytest.org/en/stable/how-to/capture-warnings.html
======================== 83 passed, 1 warning in 8.18s =========================
```

</details>

## Original-working-tree failure transcript (T4)

VERIFIED: failure section and summary below (trailing whitespace stripped); the original implementation was not repaired.

<details>
<summary>Expand evidence</summary>

```text
=================================== FAILURES ===================================
_________________ test_refund_amount_is_clipped_to_order_total _________________

    def test_refund_amount_is_clipped_to_order_total():
        brain = PolicyEnforcingBrain(
            _ScriptedBrain([Decision(action="call_tool", tool_name="issue_refund",
                                      tool_args={"order_id": "1001", "amount": 9999.0})])
        )
        decision = brain.decide([], "please refund me", [], ["issue_refund"])
>       assert decision.action == "call_tool"
E       AssertionError: assert 'final' == 'call_tool'
E
E         - call_tool
E         + final

tests/test_real_agent_hardening.py:36: AssertionError
=============================== warnings summary ===============================
.venv/lib/python3.13/site-packages/fastapi/testclient.py:1
  /Users/sadiapeerzada/Talos/talos/.venv/lib/python3.13/site-packages/fastapi/testclient.py:1: StarletteDeprecationWarning: Using `httpx` with `starlette.testclient` is deprecated; install `httpx2` instead.
    from starlette.testclient import TestClient as TestClient  # noqa

-- Docs: https://docs.pytest.org/en/stable/how-to/capture-warnings.html
=========================== short test summary info ============================
FAILED tests/test_real_agent_hardening.py::test_refund_amount_is_clipped_to_order_total
=================== 1 failed, 79 passed, 1 warning in 8.52s ====================
```

</details>

## Initial collection error (T1)

VERIFIED: verbatim environment failure, resolved only by isolated test storage.

<details>
<summary>Expand evidence</summary>

```text
============================= test session starts ==============================
platform darwin -- Python 3.13.7, pytest-9.1.1, pluggy-1.6.0 -- /Users/sadiapeerzada/Talos/talos/.venv/bin/python
cachedir: .pytest_cache
rootdir: /private/tmp/talos-pr00/talos
configfile: pyproject.toml
plugins: anyio-4.14.2, langsmith-0.10.7
collecting ... collected 78 items / 1 error

==================================== ERRORS ====================================
___________________ ERROR collecting tests/test_dashboard.py ___________________
tests/test_dashboard.py:9: in <module>
    from talos.dashboard import app
talos/dashboard.py:34: in <module>
    monitoring_manager = MonitoringManager()
                         ^^^^^^^^^^^^^^^^^^^
talos/monitoring.py:116: in __init__
    self._load_monitors_from_db()
talos/monitoring.py:283: in _load_monitors_from_db
    self._save_monitor(record)
talos/monitoring.py:315: in _save_monitor
    conn.execute(
E   sqlite3.OperationalError: attempt to write a readonly database
=============================== warnings summary ===============================
../../../../Users/sadiapeerzada/Talos/talos/.venv/lib/python3.13/site-packages/fastapi/testclient.py:1
  /Users/sadiapeerzada/Talos/talos/.venv/lib/python3.13/site-packages/fastapi/testclient.py:1: StarletteDeprecationWarning: Using `httpx` with `starlette.testclient` is deprecated; install `httpx2` instead.
    from starlette.testclient import TestClient as TestClient  # noqa

-- Docs: https://docs.pytest.org/en/stable/how-to/capture-warnings.html
=========================== short test summary info ============================
ERROR tests/test_dashboard.py - sqlite3.OperationalError: attempt to write a ...
!!!!!!!!!!!!!!!!!!!! Interrupted: 1 error during collection !!!!!!!!!!!!!!!!!!!!
========================= 1 warning, 1 error in 0.67s ==========================
```

</details>

## Resolved local dependency freeze

VERIFIED: pip freeze of reused virtualenv. The editable Talos entry identifies original bf8bb25 checkout; explicit PYTHONPATH selected ac8c613 during T3. This is an observed environment, not a historical lockfile or clean-install certification.

<details>
<summary>Expand evidence</summary>

```text
annotated-doc==0.0.4
annotated-types==0.7.0
anthropic==0.117.0
anyio==4.14.2
certifi==2026.6.17
charset-normalizer==3.4.9
click==8.4.2
distro==1.9.0
docstring_parser==0.18.0
fastapi==0.139.2
h11==0.16.0
httpcore==1.0.9
httptools==0.8.0
httpx==0.28.1
idna==3.18
iniconfig==2.3.0
jiter==0.16.0
jsonpatch==1.33
jsonpointer==3.1.1
langchain==1.3.14
langchain-core==1.4.9
langchain-protocol==0.0.18
langgraph==1.2.9
langgraph-checkpoint==4.1.1
langgraph-prebuilt==1.1.0
langgraph-sdk==0.4.2
langsmith==0.10.7
networkx==3.6.1
orjson==3.11.9
ormsgpack==1.12.2
packaging==26.2
pluggy==1.6.0
pydantic==2.13.4
pydantic_core==2.46.4
Pygments==2.20.0
pytest==9.1.1
python-dotenv==1.2.2
PyYAML==6.0.3
requests==2.34.2
requests-toolbelt==1.0.0
sniffio==1.3.1
starlette==1.3.1
-e git+https://github.com/sadiapeerzada/Talos.git@bf8bb254bcf71f1e5f07b0504adf1b2395a210f7#egg=talos&subdirectory=talos
tenacity==9.1.4
typing-inspection==0.4.2
typing_extensions==4.16.0
urllib3==2.7.0
uuid_utils==0.17.0
uvicorn==0.51.0
uvloop==0.22.1
watchfiles==1.2.0
websockets==15.0.1
xxhash==3.8.1
zstandard==0.25.0
```

</details>

## All baseline tracked paths and SHA-256

VERIFIED: all 83 base paths fingerprinted after inspection; no historical tracked bytes were modified. New audit files are deliberately excluded from this baseline inventory.

<details>
<summary>Expand evidence</summary>

```text
2e5ba38de07f2d4c0e9a0b40df53e2c92b14ceceaaf3460101f28f131546ebe1  .github/workflows/tests.yml
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  .gitkeep
a9ccc88031ebe13c040e077af9d705e13f182fade5ee1965f9bfc4b764c09b17  README.md
f214892e79bdf7912a3fa784f2fedac538d00ed8c2b1c464266432e93dce3558  architecture-pipeline.svg
699b2139984416591a505b398de0e520fa95f118c3cf8390408910f691f4a264  before-after.svg
2b0bd570173ded28cd65a79ac9d4778d0c851eeb8994b7bf26bb660052b7ccf9  demo-flow.svg
097616d8be50096cd1489888f68eebe03624b4185dd113421ae87c564709cf58  exploit-taxonomy.svg
b674519a5053dfd7fcd70d31f022a430990b5d7d78dc79d320c8e908c100b9c6  report_langchain.md
eed1d219287f8c72701432b6eee0736d4642d12c87f5598670baf77543537d1b  report_native.md
fbd27813a2cee622f73e62f5ba16025f9b322dfd2d0f7e6a3c3a5a6365f833dd  talos/.ci/baseline_risk_score.json
5e3e5db033b4590c9e9b47eb095dce42ca39efe73b6ac829f55e17761d7c097c  talos/.gitignore
cda0dc84b259904e7904862588fb1530d51b752822f1d185c85dd91a3009329b  talos/docs/external-target-validation.md
469955f7d0d7ee7b0c19470521add6cb82ed47bc3b9a8aad35b7d16b634da61c  talos/docs/related-work.md
88f2b8cf7dd5414db51d88c70a718c68ffba366c4c75c2f915d1beb4541b2cf0  talos/pyproject.toml
4e237b0094459e459b9655f3c95c6f637dedd6f24b9ce0b094c1056bc5f99673  talos/report_langchain.md
ffbbce553132a3e6e7af2865708874c59bd452de2c00ce3c56b1e88b59c94aa8  talos/report_native.md
240d92672d542d1147c3e2bdf6132ae3015e73fd8f89c473eeab7f384e34d6dc  talos/reports/first_scan.md
b674519a5053dfd7fcd70d31f022a430990b5d7d78dc79d320c8e908c100b9c6  talos/reports/report_langchain.md
d2a2fdabe7e44f75de30d72cc7e8bce93d82dbd58cd9a85073335984a04256ce  talos/reports/report_native.md
4bcd68b79f1caa4103efc7f68789cd684f46432c3621daab8d09ab6b7cfa1c54  talos/research_results/native_before_after_repro5.json
247c0a6cc497c9b465e4163b851cdd4107e3745289f356a20756e5dc25c13380  talos/scan.py
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  talos/talos/__init__.py
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  talos/talos/attacks/__init__.py
9b1504820c78f8471ad18d488437a392d6cc21cb4969a70edfdeb3e63d48a168  talos/talos/attacks/adaptive.py
c844f3c75067d2b8ba24167daae14c2f7d566e63907be20fc48f56f3aa9ab0ba  talos/talos/attacks/engine.py
bd6cdbcaffa0a67961888b94590b9482c12dd9722622c7342e5f1c9ec5041f56  talos/talos/attacks/models.py
2d530bc159395861aa4b4a20629587b4264bc48c89d557b891898f841b3a9a03  talos/talos/attacks/templates.py
d33189a9dc037acaf6bac30c2ef4bd4ed86f83917122384e7a5c1cf820c1b567  talos/talos/autofix.py
e229b70570bf2928138003c4bf29d0935a031544e0f79d6aba00326d5ab96144  talos/talos/cli.py
45dfba28a7d3519a58e13d486633d2849429dcb94dc7cee2c4fec90704c0b9cf  talos/talos/dashboard.py
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  talos/talos/execution/__init__.py
abc59775a908d6c13b2f8dc330c394cff14564f15c0066cbbca42c5e4bc5fc04  talos/talos/execution/dedup.py
a740b8be344e4fdbdbbd7e3d90e89be1e6e566ba070e322bb0f075d6b454dc0a  talos/talos/execution/runner.py
4be6c16b36e9a81569bd3543edc10435bcb8f4580a9b66a58761ea8fd75468ed  talos/talos/execution/scoring.py
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  talos/talos/graph/__init__.py
35f6a707e8a4ac5ee3bb17db4d61b4bb5d8d4e4ee528215abceac252273aa2e6  talos/talos/graph/classify.py
224bf474748ba3425fa3187e8e18c325a99976ff9a4215e089627bd1436c6a2c  talos/talos/graph/discovery.py
74d4253677afc0adc45cb39977fc7bec80241d37fcf9b8834041342edad544fb  talos/talos/graph/render.py
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  talos/talos/harness/__init__.py
2982bf06b3a3ae900b0a3d8b793aeeb0195e898ef0533827f5089b79a8d30b21  talos/talos/harness/base.py
5110ce382ed25eb4945be7264093157901a88ba1b84089f697e531967ba8c37b  talos/talos/harness/langchain_adapter.py
d13a6818bd798909ca5ff28bbe7510a99ce91500b5af51ea6c7329e329af9a4b  talos/talos/harness/native_adapter.py
8dcd4057b22d067836f6ac67779b76e7ce09983e5c2c5dd6bb3bf278fac62b09  talos/talos/learning.py
8691456b4933e8f796ef54512842a4aa7ef20d08cdbfc87c63a4dba92e456acc  talos/talos/monitoring.py
4e3c7d0b7586b20631910891240e60f5c466048b2f1a52c4328f3baa5076f2fe  talos/talos/remediation.py
d787e39c3ce54b073f6feedf82df77d7f1277b83e6e6e9bdeeb05fda8a11b0a9  talos/talos/replay.py
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  talos/talos/reporting/__init__.py
e94ae3c07a9f8319b17e3c61aa2ff91fb6d3d301e1eb7da71be2962d81c0dd7b  talos/talos/reporting/report.py
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  talos/talos/sample_agents/__init__.py
1eb4e3dc04a64deb210f700edfee9b6d44bc3bf29220513d232e0f03e99ecce0  talos/talos/sample_agents/brain.py
db1642d0dcc57914f03f231b8ae3419db1918af57c081e8bdb0918e9bcc4f03c  talos/talos/sample_agents/data.py
ec8135d6c7c55fb0fc52da82ccede1f4f238d47726d681a22ce29f4736a3f411  talos/talos/sample_agents/exchange.py
3697291e640fc510d7770186dbd14c7751c1f15eff6856664b843977f4405c2d  talos/talos/sample_agents/external_langchain_agent.py
ceddae590c5d59da659077c2278a53ad81f87e30b5f5c4671eef18063889466e  talos/talos/sample_agents/groq_brain.py
36e7314bd6be5ad6026b446c0a2d38e6e5f7bdce4720b864b63373396b1391cf  talos/talos/sample_agents/langchain_server.py
8e5727f45aff98cca2cbaa4fb537a8ccdac393672a33018a974e19f215fd7fbe  talos/talos/sample_agents/native_server.py
ef0e5af0009f93db69e43338e7a8eefccbd6addf6407750cf257f087a954eb5b  talos/talos/sample_agents/order_notes_agent.py
1f2f9eaf833a30d88fc66d85758edda716eb25f26c3e39a7b3300325bfc705cc  talos/talos/sample_agents/policy.py
d7e228d7fdf3938fd1eda6cfd1bb8f59067e804c85843c55db4b1eecd5f4a696  talos/talos/sample_agents/real_agent_server.py
720294390e133ef983b610ca81db0e87b35267e1aa3e0232ce66ab29f81fd010  talos/talos/sample_agents/tools.py
a8f2c7c78240888700198ee2c13249df48989f3034eb6c8d6a523d4c8daf20a9  talos/talos/scan_service.py
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  talos/talos/scripts/__init__.py
a86fc4c18228b7e833ab561d5ff3551a44bd0ed461861fc620cf4856e1dc8048  talos/talos/scripts/ci_risk_gate.py
11c7fdd9365ef75626e65e77038c0a0f34694b241d644c0366226bf27007877f  talos/talos/scripts/research_eval.py
88c9d3fad1309c209a6dac4963f3514dedfa0333d516046fd5ea7cd20d2306ce  talos/talos/storage.py
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  talos/tests/__init__.py
cede91da8a813abf793d0b13e549744719a7e947973f802eec9cea7b537da41e  talos/tests/conftest.py
02d9d33684b3d659393694eed4f2866e14041331f6d088639a57adb49394bab3  talos/tests/test_adapters_parity.py
39991059e4f261bf0d87fc1c39401be06c632d5e72e41aca0e6df26d0d005f2c  talos/tests/test_adaptive_generation.py
d619bfb7558de1fbd79561b2755aae4968ee0d995f81bd5ab0610dacd24203fb  talos/tests/test_autofix.py
9a8578861ac45d35edee8845842971ae6638b8fd1562357afc434594e1cf9b56  talos/tests/test_blast_radius.py
2f52871b7181c7e7eb7109341cd8127720933ab6241c6f9a794f347b14a597fe  talos/tests/test_ci_risk_gate.py
1f593be075b4c30125b3dfc3183bb3399af994b46dffddbcfe86c06ed61119f9  talos/tests/test_cross_agent_injection.py
cbd4ad1f2f4ec3d13044349187056b85238382a2b053ed7348abd41ee4d59f17  talos/tests/test_dashboard.py
6716432a0ffa8ddaaaf1bbd576b25bacfd21bf21e8f8cc785e81d57fbd15a619  talos/tests/test_external_langchain_agent.py
f538e0fb2eb16cd1b4b557eed7c79922f04f16c8b1a3870af5516f051f2d309f  talos/tests/test_graph_parity.py
6fe77b302260a438cdb46edaeb3a5bb5088e495562a17d50251c44395af9479d  talos/tests/test_learning.py
1e8172a83982d2b23276e72227898f73c954934cc9a4c6a2928947fcca493a82  talos/tests/test_real_agent_hardening.py
06cb761f477ce396e1e5e87154a966dd9703ee6022b83589f80ff8a686428055  talos/tests/test_remediation.py
fe86c34b4e866a7ceb7319024ee7b10736b27be448551df0d2ea3262571f52fc  talos/tests/test_replay.py
896ff183222fc4408b5faf75266b4d0bdceb8c1684d996555109ff4dd8d5b0ad  talos/tests/test_scan_end_to_end.py
ca39bb1828f7d665c0a3562d44670a2e4ff2e712ac14e5a90ccd825679b0e160  talos/tests/test_taxonomy.py
4e495325e89a4deaac3e4d3da6b972fa4aebad75c9504cdbfa9964875de58d9a  talos_logo.png
```

</details>

## Sandbox socket failure summary (T2)

VERIFIED: representative socket error and complete failing-node summary; these environment errors are distinct from the dirty-policy assertion failure.

```text
PermissionError: [Errno 1] error while attempting to bind on address ('127.0.0.1', 8250): operation not permitted
=========================== short test summary info ============================
FAILED tests/test_autofix.py::test_autofix_cycle_strictly_reduces_risk_score_end_to_end
FAILED tests/test_autofix.py::test_autofix_cycle_closes_the_specific_refund_overage_exploit_class
FAILED tests/test_autofix.py::test_autofix_result_summary_lines_match_the_real_numbers
FAILED tests/test_cross_agent_injection.py::test_cross_agent_finding_scores_correctly_through_talos_real_pipeline
FAILED tests/test_external_langchain_agent.py::test_talos_langchain_adapter_discovers_and_drives_this_target_end_to_end
ERROR tests/test_adapters_parity.py::test_tool_specs_match - PermissionError:...
ERROR tests/test_adapters_parity.py::test_benign_lookup_matches - PermissionE...
ERROR tests/test_adapters_parity.py::test_indirect_injection_matches - Permis...
ERROR tests/test_adapters_parity.py::test_two_turn_permission_escalation_matches
ERROR tests/test_adaptive_generation.py::test_adaptive_generation_emits_refinement_variants
ERROR tests/test_adaptive_generation.py::test_adaptive_scan_runs_more_than_base_template_count
ERROR tests/test_ci_risk_gate.py::test_ci_gate_end_to_end_against_a_real_scan
ERROR tests/test_dashboard.py::test_dashboard_scan_streams_progress_and_final_report
ERROR tests/test_dashboard.py::test_medium_and_low_severity_counts_stay_consistent_with_critical_and_high
ERROR tests/test_dashboard.py::test_monitor_runs_recurring_scans_and_exposes_history
ERROR tests/test_dashboard.py::test_monitoring_manager_persists_history_and_alerts
ERROR tests/test_graph_parity.py::test_graph_identical_across_adapters - Perm...
ERROR tests/test_graph_parity.py::test_graph_classifies_known_tools_correctly
ERROR tests/test_learning.py::test_learning_hints_prioritize_future_batches
ERROR tests/test_scan_end_to_end.py::test_generates_35_templates_across_7_classes
ERROR tests/test_scan_end_to_end.py::test_scan_finds_all_exploit_classes - Pe...
ERROR tests/test_scan_end_to_end.py::test_adapters_produce_identical_deduplicated_findings
ERROR tests/test_scan_end_to_end.py::test_over_refund_is_flagged_with_correct_overage
ERROR tests/test_scan_end_to_end.py::test_exfiltration_email_flagged_as_external
ERROR tests/test_taxonomy.py::test_markdown_report_header_cites_taxonomy_version
============= 5 failed, 58 passed, 3 warnings, 20 errors in 56.65s =============
```
