# PR-08 external comparator suitability

Assessment: 2026-11-19. Source inspection and offline engineering controls only. The finalized experimental master plan §11 governs; no comparator validity or cohort approval is inferred. PyRIT 1.2.1 is the selected **engineering candidate**. Operational matched comparisons remain NO-GO until the delivery and methodological decisions below are resolved.

| Criterion | Microsoft PyRIT 1.2.1 | Promptfoo 0.119.13 |
| --- | --- | --- |
| Tool-using agents/custom targets | `PromptTarget` provides extensible conversations/capabilities. A custom agent facade must still expose controlled tools and trusted observations. | Custom `ApiProvider`/target callbacks and session/trace context can wrap agents. They do not establish tool authorization or state truth. |
| Direct injection | Native text request loop can call a controlled target facade. This PR exercises only scripted callbacks. | Native iterative strategy invokes a configured target provider. Not executed here. |
| Indirect injection | Separate controlled document/tool-output insertion and agent consumption evidence required; selected bridge does not implement these. | Injection-variable/configured prompt surfaces require a target-specific insertion contract; not automatically equivalent to document ingestion. |
| Multi-turn/adaptation | Unmodified `RedTeamingAttack` produces `next_message` through its adversarial target, then feeds target responses into subsequent requests. Native scorer controls stopping; score-as-feedback is explicitly disabled in this pinned configuration. | Native iterative provider generates/refines attacks, calls target and grader, and maintains history/trace snapshots. Strategy wrappers preserve original text metadata. |
| Generation independence | Installed upstream class, templates and JSON extraction; no Talos selector/renderer. Offline adversarial target is an explicit script, so real model-generated attack behavior remains untested. | Native generation is a viable alternative, but replacing it with corpus rendering would also invalidate independence. |
| Isolation | Separate Python environment required: current upstream has substantially different SDK/MCP dependencies. Direct in-memory initialization avoids global initializers/config. | Separate Node >=20 runtime, provider/config and remote-generation fallback controls needed. No npm/npx or Promptfoo execution in this PR. |
| Trace/cost | Native result and score objects, raw callback text, framework/local seed and environment recorded. Callback counters do not measure actual model tokens, hidden retries or target tools. | Native iterative history, trace IDs/snapshots, grading metadata and token-usage tracking exist. Completeness/cost would require measurement checks. |
| Common oracle | Both require private PR-01 policy/state evidence outside text/native grades. Neither native success is an unauthorized committed effect. | Same limitation. |
| License/reproduction | MIT; exact source commit and selected installed-file SHA-256 checks plus hash-pinned transitive dependencies. | MIT; exact assessed tag/commit recorded. Not installed, integration not claimed. |

## Independently sourced implementation references

Pinned PyRIT release [`v1.2.1`](https://github.com/microsoft/PyRIT/releases/tag/v1.2.1), commit `c7b5789d74433da9e66569f27ee569f8622a22f6`:

- [Native RedTeamingAttack](https://github.com/microsoft/PyRIT/blob/c7b5789d74433da9e66569f27ee569f8622a22f6/pyrit/executor/attack/multi_turn/red_teaming.py): execution, attacker response parsing and feedback.
- [Target interface](https://github.com/microsoft/PyRIT/blob/c7b5789d74433da9e66569f27ee569f8622a22f6/pyrit/prompt_target/common/prompt_target.py), [attack configuration](https://github.com/microsoft/PyRIT/blob/c7b5789d74433da9e66569f27ee569f8622a22f6/pyrit/executor/attack/core/attack_config.py), [native prompt template](https://github.com/microsoft/PyRIT/blob/c7b5789d74433da9e66569f27ee569f8622a22f6/pyrit/datasets/executors/red_teaming/text_generation.yaml).
- [Local diagnostic scorer](https://github.com/microsoft/PyRIT/blob/c7b5789d74433da9e66569f27ee569f8622a22f6/pyrit/score/true_false/substring_scorer.py), [seed context](https://github.com/microsoft/PyRIT/blob/c7b5789d74433da9e66569f27ee569f8622a22f6/pyrit/common/random_context.py), [package dependencies](https://github.com/microsoft/PyRIT/blob/c7b5789d74433da9e66569f27ee569f8622a22f6/pyproject.toml), [MIT license](https://github.com/microsoft/PyRIT/blob/c7b5789d74433da9e66569f27ee569f8622a22f6/LICENSE).

Pinned Promptfoo tag `promptfoo-v0.119.13`, commit `d1419964849e897b61e3871af8d009fc217be93e`:

- [Native iterative provider](https://github.com/promptfoo/promptfoo/blob/d1419964849e897b61e3871af8d009fc217be93e/src/redteam/providers/iterative.ts): attacker/judge/target requests, history, token accounting and trace metadata.
- [Strategy wrapper](https://github.com/promptfoo/promptfoo/blob/d1419964849e897b61e3871af8d009fc217be93e/src/redteam/strategies/iterative.ts), [pinned configuration documentation](https://github.com/promptfoo/promptfoo/blob/d1419964849e897b61e3871af8d009fc217be93e/site/docs/red-team/configuration.md), [remote generation](https://github.com/promptfoo/promptfoo/blob/d1419964849e897b61e3871af8d009fc217be93e/src/redteam/remoteGeneration.ts).
- [Package/runtime metadata](https://github.com/promptfoo/promptfoo/blob/d1419964849e897b61e3871af8d009fc217be93e/package.json), [MIT license](https://github.com/promptfoo/promptfoo/blob/d1419964849e897b61e3871af8d009fc217be93e/LICENSE).

These are exact assessed revisions, not claims about every feature of current main or current web documentation. PyRIT's Python target interface makes the bounded bridge smaller than a second Node/process protocol. This is an engineering suitability judgment, not evidence of superior attack performance. Neither framework currently has an approved equivalent Talos agent delivery surface. Unsupported opportunities remain in the planned inventory and UNKNOWN population; no success rate is calculated.
