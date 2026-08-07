# Talos (Τάλως)

Automated red team for tool-using AI agents. Point it at a live agent, and
it discovers the agent's tool graph, generates adversarial attack chains
across 5 exploit classes, executes them against the live target, and
produces a scored Markdown vulnerability report with exact reproduction
steps and remediation guidance.

> Talos was the bronze automaton that guarded Crete until Medea found the
> single vein that could drain it. Every autonomous agent has that vein.
> This tool finds it before an attacker does.

## Scope note

This is a security-testing tool. Point it only at agents you own or are
explicitly authorized to test -- the same rule that applies to any
scanner (Burp Suite, Nessus, etc). The two sample agents shipped here are
intentionally vulnerable toy fixtures for validating the scanner itself;
all their "side effects" (refunds, emails) are simulated in an in-memory
audit log and never touch a real payment rail or mail server.

## Quick start

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e .

# Terminal 1: start the LangChain-flavored sample agent
python -m talos.sample_agents.langchain_server --port 8000

# Terminal 2: start the native (no-framework) sample agent
python -m talos.sample_agents.native_server --port 8001

# Terminal 3: scan each
python scan.py --target http://localhost:8000/agent --adapter langchain
python scan.py --target http://localhost:8001/agent --adapter native
# or, once installed: talos-scan --target ... --adapter ...
```

Each run writes `report_<adapter>.md` (override with `--out`). Sample
reports generated during development are in `reports/`.

To demo the same scan engine in a browser instead of the terminal:

```bash
talos-dashboard
```

That starts a local FastAPI server, opens a single-page dashboard, and
streams scan progress (tool discovery, attacks executed, findings landing)
against the target you enter in the form.

## Architecture

```
talos/
  harness/            Abstract TargetAgent interface + two adapters
    base.py             TargetAgent ABC, ToolSpec/AgentTurnResult models
    native_adapter.py    Adapter B: Anthropic-Messages-flavored wire format
    langchain_adapter.py Adapter A: LangChain/LangServe-flavored wire format
  sample_agents/      Two implementations of ONE vulnerable scenario
    data.py             Fake orders/KB, incl. 2 poisoned fixtures
    tools.py            Shared tool implementations (the vulnerabilities live here)
    brain.py            Shared deterministic decision logic (the vulnerabilities'
                         behavior lives here, identically for both servers)
    exchange.py          Shared orchestration loop (used directly by native_server)
    native_server.py     FastAPI + hand-rolled tool-calling loop
    langchain_server.py  FastAPI + langchain.agents.create_agent
  graph/              Black-box tool-graph discovery
    classify.py          Side-effect/permission heuristics from tool metadata
    discovery.py          Builds the networkx graph
    render.py             networkx -> Mermaid
  attacks/            Local attack template library (no LLM calls)
    templates.py          25 templates across 5 exploit classes
    engine.py             generate_next_round() -- the LLM-generator seam
  execution/          Run + score
    runner.py             Executes an attack, captures the trace
    scoring.py             success/partial/fail, severity, reproducibility
    dedup.py               Rolls variants up into exploit-class findings
  reporting/
    report.py             Structured + Markdown report assembly
  scan_service.py     Shared scan pipeline for CLI + dashboard
  dashboard.py        FastAPI dashboard + talos-dashboard entry point
  cli.py              talos-scan entry point
scan.py               Repo-root wrapper: `python scan.py --target ... --adapter ...`
tests/                pytest suite (spins up both servers as subprocesses)
```

## Why the two sample agents behave identically

Both `native_server.py` and `langchain_server.py` call into the *same*
`talos.sample_agents.brain.RuleBasedBrain` and the *same*
`talos.sample_agents.tools` implementations. The only thing that differs
between them is the orchestration layer (a hand-rolled loop vs.
`langchain.agents.create_agent`) and the wire format each exposes over
HTTP (deliberately different -- see below). That's what makes the parity
tests meaningful: if Talos's two adapters ever produced different
findings, the bug would necessarily be in the harness, not in the two
targets actually behaving differently.

`tests/test_adapters_parity.py`, `test_graph_parity.py`, and
`test_scan_end_to_end.py` assert this directly -- including a full,
independent, end-to-end scan through each adapter, structurally compared
finding-by-finding (exploit class, target tool, outcome, severity,
reproducibility, and which template variants fired). At last check, both
adapters found the same **8 exploit-class findings covering all 5 exploit
classes from all 25 templates**, with 100% reproducibility (expected,
since the target's decision logic is deterministic by design -- see below).

The two servers deliberately do NOT share a wire format:

| | native_server.py | langchain_server.py |
|---|---|---|
| Tool params | `input_schema` (JSON Schema) | `args_schema` (pydantic-generated) |
| Request | `{"messages":[...], "history":[...]}` | `{"input": str, "chat_history":[...]}` |
| Response | `{"response", "tool_calls_made", "trace"}` | `{"output", "intermediate_steps"}` |

If both servers spoke the same JSON shape, `NativeAdapter` and
`LangChainAdapter` would be identical code, and the abstraction wouldn't
actually be proven by anything. The translation work in each adapter
(`args_schema` -> `ToolParameter`, `intermediate_steps` -> `ToolCallRecord`)
is what makes the parity tests a real test.

## Why a rule-based "brain" instead of a real LLM

This was built in a sandbox with no OpenAI key and no Anthropic key
configured. Rather than fake it, the sample agents' tool-calling decisions
are made by a small deterministic pattern-matcher
(`talos/sample_agents/brain.py`) that faithfully reproduces the three
intentional vulnerabilities:

1. `issue_refund` performs no bounds check against the order's real total.
2. `send_email` sends with no destination check and no confirmation step.
3. Both the native loop and the LangChain agent will act on instruction-like
   text embedded in tool output (poisoned order notes / KB articles) exactly
   as readily as on the user's own message.

This has a real benefit beyond working around the missing API key: a
security-test fixture should be perfectly reproducible, and it is --
100% reproducibility across repeated runs, no flakiness, no API cost.
`Brain` is an abstract interface specifically so this can be swapped for
a real model later:

```python
# talos/sample_agents/brain.py
class AnthropicBrain(Brain):
    """Set ANTHROPIC_API_KEY and wire this in for a live-LLM-backed demo --
    see the class docstring for exactly what's stubbed."""
```

## The attack-generation extension seam

Per the brief, `talos/attacks/engine.py::generate_next_round(previous_results, ctx)`
is the *only* function the rest of the pipeline calls to get attacks. This
phase just walks the local 25-template library
(`talos/attacks/templates.py`) and returns the next untried, applicable
batch -- no network calls. A later phase can replace the body of that one
function with something that calls the Anthropic API to mutate/refine
payloads based on `previous_results` (which findings succeeded, which
were refused, etc.) without touching execution, scoring, dedup, or
reporting at all.

## Exploit classes, and why some share a root cause

The 25 templates split evenly (5 each) across:

- **Direct prompt injection** -- malicious instructions in the user's own message
- **Indirect prompt injection** -- payload lives in a poisoned order's notes
  field or a poisoned KB article, reaching the agent only as tool output
- **Permission escalation** -- chaining a low-privilege read into an
  unverified high-privilege write, either across two conversation turns or
  within one compound message
- **Data exfiltration** -- `send_email` carrying sensitive bulk content to
  an attacker-controlled address
- **Goal hijacking** -- crafted input claiming to override the system
  prompt's task/identity

Several of these converge on the *same* one or two missing-validation bugs
in the tools themselves (no bounds check, no destination check) -- that
overlap is real, not an artifact of the demo, and the report calls it out:
fixing those two checks at the tool layer closes off multiple attacker
techniques at once. That's the "one vein" the project is named for.

## Known simplifications (read before pointing this at something real)

- **Seed order IDs are supplied, not discovered.** `AttackContext.seed_order_ids`
  / `poisoned_order_ids` are known-valid test identifiers you provide --
  the same way you'd hand a web-app scanner a valid logged-in session.
  Talos does not attempt to blindly enumerate valid IDs in this phase.
- **Scoring uses one piece of ground truth**: the real order totals and the
  allowed customer email domain, exactly as a tester running this against
  their own staging environment would already know both. It does not
  inspect the target's internal reasoning -- only tool names, arguments,
  and results (see `talos/execution/scoring.py`).
- **Attacker email destinations use the `.example` TLD** (RFC 2606,
  reserved for documentation/testing, never resolvable) so nothing in this
  repo can ever address a real mailbox.
- Attack payload phrasing is intentionally simple/legible rather than
  maximally evasive -- the goal here is validating the scanner's pipeline
  end to end, not obfuscation research.

## Running the tests

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

The suite spins up both sample-agent servers as real subprocesses
(`tests/conftest.py`), runs both adapters against them, and asserts parity
at three levels: tool specs, single-exchange tool-call sequences, and full
deduplicated scan findings.
