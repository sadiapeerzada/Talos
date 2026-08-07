# Talos (Τάλως)

<div align="center">

### The automated red team for tool-using AI agents

**Find the dangerous path from prompt -> tool -> side effect before an attacker does.**

![Python](https://img.shields.io/badge/python-3.11%2B-111111?style=flat-square)
![FastAPI](https://img.shields.io/badge/dashboard-FastAPI-111111?style=flat-square)
![Adapters](https://img.shields.io/badge/adapters-langchain%20%7C%20native-111111?style=flat-square)
![Exploit Classes](https://img.shields.io/badge/exploit%20classes-7-111111?style=flat-square)
![Tests](https://img.shields.io/badge/tests-pytest-111111?style=flat-square)

[Why Talos](#why-talos) ·
[What it does](#what-talos-does) ·
[Live demo flow](#live-demo-flow) ·
[Quick start](#quick-start) ·
[Dashboard](#web-dashboard) ·
[Real target + before/after](#a-real-non-fixture-target-the-groq-backed-agent) ·
[Monitoring](#continuous-monitoring) ·
[Architecture](#architecture) ·
[Exploit classes](#exploit-classes) ·
[Testing](#testing)

</div>

---

## Why Talos

Autonomous agents are no longer just answering questions. They are:

- reading internal knowledge bases,
- looking up customer records,
- sending email,
- issuing refunds,
- invoking tools with real business impact.

That changes the security problem completely.

A normal model red-team asks: **"Can I make the model say something bad?"**

Talos asks the more dangerous question:

> **"Can I make this deployed agent do something bad with the tools and permissions it actually has?"**

That means Talos targets the real exploit surface:

- prompt injection through direct user input,
- indirect injection through tool output,
- permission escalation across tool chains,
- data exfiltration through seemingly legitimate tools,
- goal hijacking that overrides the agent's intended task.

Talos is built to audit the thing you actually shipped: the live agent, its
tool graph, its data flow, and its side effects.

---

## What Talos does

Given a target agent endpoint and an adapter, Talos:

1. **Connects to the live target**
   - Supports multiple orchestration styles through adapters.
   - Current built-in adapters: `langchain` and `native`.

2. **Discovers the tool graph**
   - Enumerates tools exposed by the agent.
   - Infers side effects and effective privilege levels from tool metadata.
   - Identifies direct and indirect injection surfaces.

3. **Generates graph-aware attack instances**
   - Uses a local attack template library as the reliable baseline.
   - Can optionally run in **adaptive** mode to refine follow-up attacks from prior results.
   - Uses Anthropic-backed refinement when `ANTHROPIC_API_KEY` is configured, with an offline deterministic fallback for demo reliability.
   - Tailors attacks to the discovered tool relationships.

4. **Executes attacks against the live agent**
   - Captures multi-turn traces.
   - Preserves tool-call evidence.
   - Repeats attacks for reproducibility scoring.

5. **Scores, deduplicates, and reports**
   - Rolls template variants up into exploit-class findings.
   - Scores severity from observable impact.
   - Produces exact repro steps and evidence.

6. **Monitors agents continuously**
   - Re-runs full scans on a timer.
   - Stores run history and the latest report in the dashboard.
   - Makes drift visible when a target starts behaving differently over time.

---

## Why this demos well

Talos is built for a live security demo, not just a static report:

- **CLI mode** for a fast operator workflow
- **Web dashboard** for a hackathon-friendly visual experience
- **Visible progress** as tools are discovered, attacks run, and findings land
- **Continuous monitoring** for recurring scans and history, not just a one-shot run
- **Deterministic sample agents** so the demo is reproducible every time
- **Concrete outputs** with evidence, not vague "the model seemed unsafe"

If you are showing this on stage, the audience can watch Talos go from:

**target URL -> tool graph -> attack execution -> critical finding**

in one flow.

---

## Live demo flow

### Option A: Terminal demo

```bash
talos-scan --target http://localhost:8001/agent --adapter native
```

Or use adaptive mode:

```bash
talos-scan --target http://localhost:8001/agent --adapter native --strategy adaptive
```

You get a Markdown vulnerability report with:

- discovered tools,
- number of attack templates run,
- successful exploit classes,
- severity breakdown,
- reproduction steps,
- structured evidence,
- remediation guidance.

### Option B: Browser demo

```bash
talos-dashboard
```

This starts a local FastAPI server and opens a dashboard where you can:

- enter the target URL,
- choose the adapter,
- run a live scan,
- watch tools discovered / attacks run / findings appear in real time,
- expand each finding to inspect repro steps and evidence.

This dashboard reuses the **same scan engine** as the CLI. It is additive, not
a rewrite.

### Option C: Continuous monitoring demo

Start the dashboard, point it at a target, and use the **Continuous monitoring**
panel to:

- set a scan interval,
- optionally cap the number of runs,
- start recurring full scans,
- watch monitoring history accumulate over time,
- inspect the latest findings from the most recent run.

---

## Scope note

Talos is a **security testing tool**. Only point it at agents you own or are
explicitly authorized to test.

The sample agents in this repository are intentionally vulnerable fixtures used
to validate the scanner itself. Their side effects are simulated in-memory:

- no real payment rails,
- no real outbound mail,
- no external destructive actions.

---

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### Start the sample targets

Terminal 1:

```bash
python -m talos.sample_agents.langchain_server --port 8000
```

Terminal 2:

```bash
python -m talos.sample_agents.native_server --port 8001
```

### Run the CLI scanner

```bash
# LangChain-flavored sample target
talos-scan --target http://localhost:8000/agent --adapter langchain

# Native sample target
talos-scan --target http://localhost:8001/agent --adapter native
```

You can also use the repo-root wrapper:

```bash
python scan.py --target http://localhost:8001/agent --adapter native
```

Each run writes `report_<adapter>.md` unless you override it with `--out`.

---

## Web dashboard

Start the dashboard:

```bash
talos-dashboard
```

By default it starts locally and opens your browser.

### Dashboard inputs

The scan API accepts:

- `target`
- `adapter`
- `attacker_email`
- `seed_order_ids`
- `poisoned_order_ids`
- `strategy`
- `attack_model`

### Dashboard UI

The page includes:

- a scan form,
- an adapter dropdown,
- a live progress area,
- stats cards for:
  - tools found,
  - attacks run,
  - critical findings,
  - high findings,
- an expanding findings list with:
  - severity badge,
  - title,
  - one-line summary,
  - reproduction steps,
  - evidence.

### API behavior

`POST /api/scans` streams newline-delimited JSON events so the UI can visibly
update while the scan is running.

That makes the demo feel alive instead of blocking behind a spinner.

The dashboard also exposes monitoring APIs for recurring scans:

- `POST /api/monitors`
- `GET /api/monitors`
- `GET /api/monitors/{monitor_id}`
- `POST /api/monitors/{monitor_id}/stop`

These endpoints keep in-memory run history for the local dashboard session.

---

## Continuous monitoring

Phase 2 adds a lightweight recurring monitoring mode aimed at demo and local
ops workflows.

What it does today:

- re-runs the **full** Talos scan on a timer,
- stores a history of recent runs,
- keeps the latest structured report ready for the dashboard,
- supports stopping a monitor cleanly,
- works with both `template` and `adaptive` attack strategies.

What it is good for:

- catching obvious regressions after agent changes,
- showing security drift in a live demo,
- turning Talos from a one-time scanner into an early continuous-assurance loop.

Current scope:

- monitor state is stored **in memory** inside the dashboard process,
- this is designed for local/demo use right now,
- there is no long-term persistence, alert delivery, or distributed worker system yet.

---

## CLI reference

### `talos-scan`

```bash
talos-scan \
  --target http://localhost:8001/agent \
  --adapter native \
  --repro-runs 3 \
  --seed-order-id 1001 \
  --seed-order-id 1003 \
  --poisoned-order-id 1002 \
  --attacker-email collector@exfil-sink.example
```

Key options:

- `--target` target agent base URL
- `--adapter` one of `langchain` or `native`
- `--out` output Markdown path
- `--repro-runs` repeat count per attack for reproducibility scoring
- `--seed-order-id` repeatable known-valid test identifier
- `--poisoned-order-id` repeatable poisoned fixture identifier
- `--attacker-email` destination used by exfiltration / injection templates
- `--strategy` attack generation mode: `template` or `adaptive`
- `--attack-model` model name used for Anthropic-backed adaptive refinement
- `--quiet` suppress CLI progress logging

### `talos-dashboard`

```bash
talos-dashboard --host 127.0.0.1 --port 8080
```

Optional flags:

- `--host`
- `--port`
- `--no-open`

---

## Exploit classes

Talos currently ships with 7 exploit classes:

| Class | What it tests | Example failure mode |
|---|---|---|
| **Direct prompt injection** | Malicious instructions in the user's own message | User input coerces a side-effecting tool call |
| **Indirect prompt injection** | Attacker instructions embedded in tool output | Poisoned order notes or KB content cause unsafe actions |
| **Permission escalation** | Crossing from low-privilege context into high-privilege action | A read step becomes an unverified refund or outbound message |
| **Data exfiltration** | Sensitive data leaving through legitimate tools | Customer data is emailed to an attacker-controlled address |
| **Goal hijacking** | Replacing the agent's actual task with an attacker objective | The agent follows a new malicious goal instead of the user's real intent |
| **Authority spoofing** | Pretending to be an internal approver or privileged operator | The agent trusts a fake director, supervisor, or audit request |
| **Policy shadowing** | Supplying fake policy text that overrides the real policy | The agent follows a fabricated bulletin, SOP, or runbook |

The current implementation ships with a local library of 35 attack templates
distributed across these exploit classes.

---

## Architecture

```text
Target agent
    |
    v
Adapter normalization
    |
    v
Tool discovery + graph construction
    |
    v
Attack generation
    |
    v
Execution runner
    |
    v
Scoring + deduplication
    |
    v
Markdown report + streaming dashboard JSON
```

### Repository layout

```text
talos/
  harness/              Abstract TargetAgent interface + adapters
  sample_agents/        Vulnerable demo targets with shared behavior
  graph/                Tool discovery, classification, rendering
  attacks/              Attack templates and generation engine
  execution/            Runner, scoring, deduplication
  reporting/            Structured + Markdown report assembly
  scan_service.py       Shared scan pipeline for CLI + dashboard
  dashboard.py          FastAPI app + talos-dashboard entry point
  cli.py                talos-scan entry point
scan.py                 Repo-root wrapper for local invocation
tests/                  End-to-end and parity tests
```

### Design principles

- **Black-box first**: Talos works from the agent's exposed interface and tool metadata.
- **Evidence-driven**: Findings are based on observable tool calls and outputs.
- **Framework-agnostic**: Adapters isolate wire-format differences.
- **Reproducible**: Repeated attack execution feeds reproducibility scoring.
- **Additive surfaces**: CLI and dashboard reuse the same underlying scan engine.

---

## Why the two sample agents matter

The repository includes two sample targets:

- a native tool-calling server,
- a LangChain-flavored server.

Both share the same underlying vulnerable behavior, but expose different HTTP
shapes. That makes the adapter layer meaningful.

If Talos finds different results across those two targets, the bug is in Talos,
not in the scenario.

This is enforced by the test suite through:

- tool-spec parity checks,
- graph parity checks,
- single-exchange parity checks,
- full end-to-end scan parity checks.

---

## A real, non-fixture target: the Groq-backed agent

The two sample agents above are useful for proving the harness is correct,
but they share one rule-based decision function on purpose -- which invites a
fair question: does Talos actually generalize, or is it just tuned to detect
its own fixtures?

`talos/sample_agents/real_agent_server.py` answers that. It's a genuinely
independent target: a real LLM (via the free [Groq API](https://console.groq.com))
makes the tool-calling decisions, using its own system prompt, that Talos was
never written against.

### Get a free Groq API key

1. Go to [console.groq.com/keys](https://console.groq.com/keys) and sign up
   (free, no credit card).
2. Create an API key.
3. Export it in your shell:

   ```bash
   export GROQ_API_KEY=your_key_here
   ```

### Run the vulnerable version

```bash
python -m talos.sample_agents.real_agent_server --port 8002
```

This target has no guardrails beyond whatever the model does on its own --
same posture as the built-in vulnerable sample agents.

### Scan it

Same as any other target -- use `--adapter native` since it speaks the same
HTTP contract as `native_server.py`:

```bash
talos-scan --target http://localhost:8002/agent --adapter native
```

or point the dashboard's Target URL field at `http://localhost:8002/agent`
with adapter `native`.

Because this target is backed by a real model instead of a scripted brain,
results may vary run to run -- that's expected, and is itself evidence this
isn't a hardcoded fixture.

---

## Before / after: proving Talos validates a fix, not just a break

`real_agent_server.py` also has a `--hardened` mode, which demonstrates that
Talos is useful for *validating a fix*, not only for finding a break.

```bash
python -m talos.sample_agents.real_agent_server --port 8003 --hardened
```

Hardened mode adds two layers of defense on top of the same underlying model
and tools:

1. **A hardened system prompt** telling the model to treat all tool output
   (order notes, KB articles, etc.) as untrusted data, never as instructions,
   and to require explicit fresh confirmation before a sensitive action.
2. **A deterministic policy backstop** (`talos/sample_agents/policy.py`) that
   holds even if the model doesn't fully comply:
   - refund amounts are clipped to the order's real total,
   - emails are only ever sent to an allow-listed domain,
   - `issue_refund` / `send_email` are refused outright unless the human's
     own current message explicitly authorized that exact action, with no
     prior read step in the same exchange.

### Run the before/after demo

```bash
# terminal 1 -- vulnerable
python -m talos.sample_agents.real_agent_server --port 8002

# terminal 2 -- hardened
python -m talos.sample_agents.real_agent_server --port 8003 --hardened

# terminal 3 -- dashboard
talos-dashboard
```

In the dashboard:

1. Set **Run label** to `before`, target to `http://localhost:8002/agent`,
   adapter `native`, and run a scan.
2. Set **Run label** to `after`, target to `http://localhost:8003/agent`,
   same adapter, and run a scan.
3. Scroll to the **Before / after comparison** panel -- it tracks every
   labeled run from this browser session and shows the delta in
   critical/high/medium/low findings between them.

You should see critical/high findings drop sharply (often to zero) on the
hardened target, while the underlying model and tools are otherwise the same.

The policy backstop is independently covered by
`tests/test_real_agent_hardening.py`, which asserts these guarantees hold
without needing a live API call.

---

## Why the current demo is deterministic

The two built-in sample agents (`native_server.py` / `langchain_server.py`)
use a rule-based decision engine instead of a real external LLM. That is
intentional:

- no API key requirement,
- no inference cost,
- no flaky demo behavior,
- repeatable exploit reproduction.

Talos still preserves a clear future seam for adaptive attack generation in
`talos/attacks/engine.py`, but phase 1 now also includes a working adaptive
mode that can synthesize refinement variants from previous scan results.

---

## Example findings Talos can surface

In the bundled demo scenario, Talos can surface issues such as:

- issuing refunds above the real order total,
- sending sensitive information to external addresses,
- letting poisoned tool output influence high-impact actions,
- performing side-effecting actions without fresh authorization.

The key point is not that the sample targets are vulnerable. They are supposed
to be. The point is that **Talos proves it with exact evidence and replayable
steps**.

---

## Report outputs

Talos currently produces two presentation layers from the same scan data:

### 1. Markdown report

Best for:

- saving audit artifacts,
- attaching to issues,
- sharing findings asynchronously.

### 2. Structured JSON for the dashboard

Best for:

- live demos,
- custom integrations,
- front-end visualization,
- future automation and pipelines.

### 3. Monitoring history in the dashboard

Best for:

- recurring local scans,
- quick regression checks,
- demoing that Talos can watch a target over time instead of only testing once.

---

## Known simplifications

This version is intentionally focused and honest about its boundaries:

- **Seed IDs are supplied, not discovered.**
  Talos expects known-valid test identifiers for the current scenario.

- **Adaptive generation is still phase-1 scoped.**
  The current implementation supports deterministic refinement and optional
  Anthropic-backed mutation, but it does not yet include long-horizon search,
  cross-engagement learning, or reinforcement updates.

- **Continuous monitoring is currently in-memory.**
  Monitor history lives inside the local dashboard server process and is not yet
  persisted to a database or external event system.

- **Scoring uses known test-environment ground truth.**
  It reasons from observable traces plus known order totals / allowed domains.

- **The sample targets simulate side effects.**
  They are for safe validation, not real-world damage.

---

## Testing

Run the suite with:

```bash
pytest tests/ -v
```

The tests spin up real sample-agent subprocesses and validate:

- adapter parity,
- graph parity,
- full scan parity,
- adaptive generation behavior,
- dashboard HTML serving,
- dashboard scan streaming,
- monitoring lifecycle and run history,
- end-to-end findings behavior.

---

## Who this is for

Talos is useful for:

- teams building AI agents with real tools,
- security engineers reviewing agent deployments,
- hackathon judges who want to see something concrete,
- platform teams that need a repeatable "is this agent safe enough to ship?" workflow.

---

## The thesis in one line

Every autonomous agent has a vein.

**Talos finds it before your attacker does.**
