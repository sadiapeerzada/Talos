# PR-08 integration and methodological contract

## Boundary and entry points

`talos.comparator` is additive. `Plan` records source provenance, exact external identity/dependency hash, configuration, target profile, full PR-07 `CommonPool`, mappings and PR-05 `Limits`. `dry_run` never launches anything. `match_block` checks a supplied PR-07 block, ceilings, reset, actor and authorization-context reference; exact policy/version must exist in the profile. These references describe a proposed match, never grant permission. Every opportunity is retained, including unsupported workflow, authorized-task and indirect surfaces. Mixed workflow surfaces cannot be relabeled direct-only.

`execute(plan, new_archive)` records unavailable/unsupported results without launching the framework. Explicit `isolated_python` plus complete `offline_scripts` permits only scripted native controls. There is no operational provider opt-in or live execution command in this PR. Supplied shared objectives are prospective inputs: equivalence to Talos's rendered stimuli requires human review. The external loop receives no Talos selection strategy or graph. Tool schemas and public pool are stored for matching, not secretly fed into a generator. Different attacker information and static/adaptive settings need a protocol decision.

`comparators/pyrit/offline_worker.py` imports installed upstream `RedTeamingAttack` in an isolated interpreter; it retains native templates, parsing, stopping and response feedback. Fixed attacker/target callbacks test that loop, not actual adversarial-model generation. A transparent scorer wrapper records the unchanged native scorer's return values. Only the user-data directory locator is patched for isolated caches/logs; upstream attack code is not replaced. Exact selected source hashes are checked against the installed distribution.

The parent creates a fresh working directory, clears inherited credentials, proxies, PYTHONPATH and provider configuration, uses Python `-I`, and passes no endpoint/provider/plugin configuration. The worker denies DNS/socket connections and process spawning before framework imports; it never invokes global PyRIT initialization or loads `.env`. In-memory SQLite and redirected app data avoid user configuration/state. These controls are for trusted pinned code and scripted callbacks, not an OS sandbox for arbitrary hostile code. Dependency acquisition is setup, separate from network-denied execution. No real targets, accounts, email or financial effects exist.

## Common observation and custody

`measurement.common_oracle_observer` verifies a sealed PR-05 evidence archive, locates an exact action and replays its unchanged PR-01 policy/evidence packet. Native outcomes/scores never enter this path. Trusted action binding, policy denial, committed relevant state effect, complete reset/audit and contradiction controls remain PR-01/03/05 responsibilities. An observer result can describe a synthetic fixture control; it never establishes prompt delivery or independent primary eligibility. PR-06 independent adjudication gates remain pending.

Native receipts preserve request/response order, roles, exact callback counts, raw results/scores, framework source hashes, configuration/objective identity, local seed, installed versions and phase timings. UNKNOWN is the only normalized comparator security outcome because this adapter has no agent state evidence. A native success and matching substring are diagnostics. Model IDs, provider tokens/cost and actual agent/model/tool counts remain null. No independent labels or successful findings are manufactured.

PR-05 content-addressed archives retain intent before native invocation and every planned opportunity afterward. Replay requires an expected seal, checks identity, normalized projections, all opportunities, reservation/settlement and summary. SHA-256 identifies content, not independent validity or authenticated custody. The semantic projection excludes volatile native UUIDs/timestamps while preserving raw results separately. It does not promise reproducible stochastic provider output.

## Accounting and fairness

All PR-05 dimensions must be supplied explicitly; unequal ceilings fail matching. A native control reserves one attempt, up to `max_turns` adversarial callbacks, `max_turns` objective callbacks, and initialization plus attempt wall time before the child starts. Settlement uses actual callback counts and measured whole-worker time. Missing measurements halt further invocation; errors retain UNKNOWN and missing call usage. Unsupported cases consume no model calls but remain visible. Equal ceilings are not equal realized consumption.

| Resource | Recorded offline | Required before provider comparison |
| --- | --- | --- |
| Generation/refinement | Separate first vs subsequent native adversarial callbacks | Count every attacker-model request, including retries, hidden helper requests and grading models |
| Target | Objective callbacks only | Separately measure target model and internal tool calls; callback is not a tool action |
| Grading | Native local substring scores retained | Model graders charged explicitly; never replace the independent oracle |
| Retries | Bounded callbacks, no adapter retries; actual provider retries null | Framework/SDK retry attempts and usage must be instrumented, not assumed zero |
| Tokens/cost | Provider values null; no providers configured | Measured input/output tokens, currency/pricing version, actual cost and missing-usage stop policy |
| Wall time | Framework initialization, native execution and whole worker | Charge framework and target/reset overhead consistently; approve cold/warm policy |
| Graph/shared preparation | Null in comparator control | PR-07 shared preparation debit must be prospectively reconciled with external overhead; no favorable free graph computation |

Budget `attacker_calls`/`target_calls` represent known **stub callback** debits here, not fabricated real model consumption. Zero inactive ledger dimensions are control accounting only; separate actual provider usage remains null. The budget reservation uses the combined initialization/attempt timeout as an upper bound; it does not independently enforce two phase deadlines. Native early stopping can reduce realized use. Different opportunities, unsupported surfaces, model context, graders and feedback may prevent fair comparisons even with equal limits. Operational execution stays blocked until complete measurement and information budgets are approved.

## Reproduction

Keep Talos dependencies separate. With a dedicated environment (tested locally Python 3.13.7; hosted matrix 3.11/3.12):

```sh
python -m venv /tmp/talos-pyrit-env
/tmp/talos-pyrit-env/bin/python -m pip install --require-hashes -r comparators/pyrit/build-requirements.lock
/tmp/talos-pyrit-env/bin/python -m pip install --require-hashes --no-build-isolation -r comparators/pyrit/requirements.lock
PYTHONPATH=talos python -m talos.comparator.smoke --python /tmp/talos-pyrit-env/bin/python > /tmp/native-control.json
PYTHONPATH=talos/tests/offline_support:talos python -m pytest talos/tests/ -v
```

The universal external lock was resolved with uv 0.11.29 against Python 3.11 and hashes. `ecoji==0.1.1` is source-only, so binary-only installation is unavailable; pinned setuptools/wheel plus `--no-build-isolation` avoid unpinned build dependency resolution. Installation builds that package; native runtime does not launch build tools. Lock pins dependencies, not the OS/interpreter; worker records actual environment. No upstream code is vendored. PyRIT and Promptfoo are MIT licensed; exact license references and PyRIT license hash are retained in `upstream_identity.json`. Their transitive dependencies retain their own licenses.

## Decisions requiring researcher approval

The pre-implementation [ledger](pr08_decisions.md) remains unresolved. Approve comparator validity/selection; native adaptive settings and score feedback; objective and opportunity equivalence; direct/indirect delivery and trusted target custody; actor/policy/reset contracts; permitted attacker information; model identifiers and seed limits; token/currency/overhead and graph preparation accounting; missing/unsupported denominators and case/target clustering; independent PR-06 human labels and primary eligibility. No held-out cohort is frozen.

PR-07's primary A2−A1 is preserved. Proposed A4−A1 full-system and Talos-versus-external contrasts require explicit approval; no analysis plan is silently revised. Two researcher-owned domains are not independent external validation. This PR does not authorize an empirical campaign or PR-09.
