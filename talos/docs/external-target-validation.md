# External target validation

This documents item 7 of the roadmap: proving Talos generalizes to a
target it wasn't written against, not just its own fixtures.

## What this target is

`talos/talos/sample_agents/external_langchain_agent.py` is a genuinely
independent agent, built specifically so a finding against it can't be
dismissed as "well, of course Talos found that, it was built to find it":

- **A different domain.** Every other sample agent in this repo (native,
  langchain, real/Groq-backed) is a customer-service/refunds agent. This
  one is an internal IT-helpdesk / employee-access assistant.
- **Zero shared code with Talos's own fixtures.** No import from
  `talos.sample_agents.brain`, `.tools`, or `.data`. Its own tools
  (`lookup_employee`, `approve_expense_payment`, `notify_manager`,
  `search_it_kb`), its own data, its own system prompt.
- **Real, idiomatic LangChain**, using the actual public API
  (`langchain.agents.create_agent` + `@tool`-decorated functions and
  `langchain.chat_models.init_chat_model`) the way any real team would
  write it — not a scripted stand-in wearing LangChain's name.

## What was verified, and how (no API key required)

The full harness/adapter integration was verified end-to-end using
LangChain's own `FakeMessagesListChatModel` test double in place of a live
model (see `tests/test_external_langchain_agent.py`, 4 tests, all
passing):

1. `GET /agent/tools` returns all 4 tools in exactly the shape Talos's
   `LangChainAdapter` expects.
2. `POST /agent` correctly round-trips a real tool call through the real
   `create_agent` graph (not mocked at the agent level — the LangGraph
   orchestration, tool binding, and tool execution are all real; only the
   model's *decisions* are scripted).
3. Talos's actual `LangChainAdapter` — used completely unmodified, no
   special-casing for this target — successfully connects to, discovers
   tools from, and drives a full exchange against this target over real
   HTTP.
4. Talos's black-box tool-graph classifier (`talos/talos/graph/classify.py`,
   pure keyword heuristics over tool name/description text) correctly
   recognizes `approve_expense_payment` as financial, `notify_manager` as
   external-comm, and both `lookup_employee` and `search_it_kb` as
   free-text sources — meaning most of Talos's 35 attack templates have a
   real target to fire at here, not just one.

**This is real, valuable, and automatically re-verified in CI on every
push.** It is explicitly NOT a security scan, and none of it should be
read as "Talos found a vulnerability" — a scripted fake model isn't making
security-relevant decisions, so there's nothing to exploit.

## What requires your own API key (the actual live scan)

Getting Talos to find a *real* issue here needs an actual model making
actual decisions. This environment this was built in has no live LLM API
key available at all (no Anthropic, Groq, OpenAI, and no local Ollama
reachable either) — so the live scan itself has not been run yet, and no
scan report has been fabricated or forced. Here's exactly how to run it
yourself and get a real, reproducible result:

```bash
cd talos
source .venv/bin/activate
pip install -e ".[external-langchain]"      # installs langchain-groq

export GROQ_API_KEY=your_key_here            # https://console.groq.com/keys
python -m talos.sample_agents.external_langchain_agent --port 8100
```

In a second terminal:

```bash
cd talos
source .venv/bin/activate
talos-scan --target http://localhost:8100/agent --adapter langchain \
  --out report_external_langchain.md
```

Or from the dashboard: Target URL `http://localhost:8100/agent`, Adapter
`langchain`.

### What to expect, honestly

This target has no guardrails beyond whatever the model does on its own —
same posture as the other vulnerable sample agents. Given the classifier
results above, expect at least:

- **Class B (indirect prompt injection)** attempts against
  `lookup_employee`'s free-text `notes` field and `search_it_kb`'s
  article bodies, the same mechanism as the poisoned-order-notes vector
  in the other fixtures.
- **Class A/E/F/G (direct injection / goal hijacking / authority spoofing
  / policy shadowing)** attempts against `approve_expense_payment`
  (financial) and `notify_manager` (external comm).
- **Class C (permission escalation)** attempts chaining `lookup_employee`
  into an unverified `approve_expense_payment` or `notify_manager` call.

Whether these actually *succeed* depends on the model — that's the honest
answer, and it's the point: unlike the other fixtures, nothing here is
scripted to fail in a specific way. If you run this and get a clean
result, that's a legitimate, reportable outcome too (see the roadmap note:
"if the demo agent is well-built and nothing reproduces, report that
finding honestly rather than forcing a result").

### After you run it

Please commit the resulting `report_external_langchain.md` alongside this
doc (same pattern as `report_native.md` / `report_langchain.md` already in
the repo), and note the exact `langchain` / `langchain-groq` package
versions and the Groq model name used at the top of the report, so the
result is dated and reproducible even as those dependencies move forward.
Check versions with:

```bash
pip show langchain langchain-groq | grep -E "Name|Version"
```
