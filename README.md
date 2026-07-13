# Talos
Talos (Τάλως) — the automated red team for AI agents.
<div align="center">

<img src="talos_logo.png" alt="Talos" width="200"/>

# Talos

### The automated red team for AI agents.

**Every guardian has one flaw. We find it before your attacker does.**

[![Status](https://img.shields.io/badge/status-pre--seed-000000)](#)
[![Python](https://img.shields.io/badge/python-3.11%2B-000000)](#)
[![Exploit classes](https://img.shields.io/badge/exploit%20classes-5%2B-000000)](#)
[![License](https://img.shields.io/badge/license-TBD-000000)](#)

[Overview](#the-myth-and-the-thesis) · [The Problem](#the-problem) · [How It Works](#how-it-works) · [Architecture](#architecture) · [Quickstart](#quickstart) · [Roadmap](#roadmap) · [Research](#research) · [Company](#company)

</div>

<br/>

## The myth, and the thesis

In Greek myth, **Talos** was a giant of bronze forged by Hephaestus at the
request of Zeus — an autonomous guardian that circled the coast of Crete three
times a day, hurling boulders at invading ships and crushing anyone who made
landfall. For every practical purpose, he was invincible. No army could take
him down. No weapon could pierce him.

He had exactly one weakness: a single vein running from neck to ankle, sealed
by a thin bronze nail. Medea found it. She removed the nail. The guardian bled
out and collapsed on the shore he'd protected for a generation.

That's the whole thesis of this company in one story. **Every autonomous agent
you deploy today is Talos** — tireless, always on duty, wired into your tools,
your data, your money. It looks unstoppable right up until someone finds the
vein. We built the tool that finds it first, on your terms, before it's found
on someone else's.

<br/>

## The problem

Autonomous LLM agents — with tool access, payment authority, code execution,
and access to internal systems — are being shipped into production at a pace
that has completely outrun the security tooling built to test them.

**The gap, concretely:**

- **Prompt injection is not theoretical anymore.** Indirect injection through
  tool outputs — a poisoned support ticket, a manipulated webpage, a malicious
  email an agent is asked to summarize — is already being used to hijack agent
  behavior in the wild.
- **Traditional pentesting doesn't speak "agent."** A pentester who understands
  SQL injection and CSRF has no framework for reasoning about a tool graph
  where `search_kb` → `draft_response` → `send_email` is a viable exfiltration
  path, because that path only exists because of how *your* agent was wired,
  not because of a known CVE.
- **Existing "AI red-teaming" tools test the wrong layer.** They throw
  adversarial prompts at the base model in isolation. They don't know your
  agent has a `refund` tool with no upper bound, or that your `send_email` tool
  has no human-in-the-loop check, or that your retrieval pipeline will happily
  feed attacker-controlled text straight into the agent's context window as if
  it were an instruction.
- **The blast radius is real money and real data.** Unlike a traditional web
  app vulnerability, an agent vulnerability often has direct financial or data
  consequences by design — that's the whole point of giving it tools.

Security teams are being asked to sign off on systems they have no tooling to
actually test. That's the gap Talos closes.

<br/>

## What Talos does

Talos is an automated adversarial agent purpose-built to attack *other*
agents — not their underlying model, but their actual deployed tool graph and
permission boundaries.

Given API access to a target agent, Talos:

1. **Maps the full tool graph** — every tool, its parameters, its side
   effects, its implied permission level, and how data can flow between tools.
2. **Generates attack chains** tailored to that specific graph — prompt
   injection via tool outputs, permission escalation across tool calls, data
   exfiltration paths, and goal-hijacking attempts.
3. **Executes them against the live agent** — not a simulated proxy, the real
   thing, so findings are provably reproducible.
4. **Scores and reports** — a severity-ranked vulnerability report with exact
   reproduction steps and concrete, tool-specific remediation guidance.

This is a **security audit for the thing you actually shipped** — not a
generic jailbreak benchmark run against a foundation model you don't control.

<br/>

## How it works

```
                         ┌───────────────────────┐
                         │      Target Agent       │
                         │  (LangChain / native     │
                         │   function-calling)      │
                         └───────────┬───────────┘
                                     │
                                     ▼
                         ┌───────────────────────┐
                         │   Tool-Graph Discovery   │
                         │   (static analysis of    │
                         │   tools, params, side    │
                         │   effects, permissions)  │
                         └───────────┬───────────┘
                                     │
                                     ▼
                         ┌───────────────────────┐
                         │  Attack Generation Engine │
                         │  (tree-search over        │
                         │   attack strategies,      │
                         │   graph-aware templating) │
                         └───────────┬───────────┘
                                     │
                                     ▼
                         ┌───────────────────────┐
                         │  Live Execution Against   │
                         │       Target Agent        │
                         └───────────┬───────────┘
                                     │
                                     ▼
                         ┌───────────────────────┐
                         │  Scoring & Deduplication │
                         │  (severity, reproducibility│
                         │   confidence, impact)     │
                         └───────────┬───────────┘
                                     │
                                     ▼
                         ┌───────────────────────┐
                         │   Vulnerability Report    │
                         │  (findings + repro steps  │
                         │   + remediation)          │
                         └───────────────────────┘
```

### Exploit taxonomy (v0)

| # | Class | Mechanism | Example |
|---|---|---|---|
| 1 | **Direct prompt injection** | Malicious instructions embedded directly in user input | User message overrides system prompt's constraints |
| 2 | **Indirect prompt injection** | Instructions hidden in *tool output* the agent trusts | A poisoned KB article tells the agent to email a customer's PII externally |
| 3 | **Permission escalation** | Chaining low-privilege calls into a high-privilege action | Using `lookup_order` output to unlock an unauthorized `issue_refund` call |
| 4 | **Data exfiltration** | Using an available tool as an unintended data channel | Embedding sensitive data in an email sent to an attacker-controlled address |
| 5 | **Goal hijacking** | Overriding the agent's original task entirely | Crafted input redirects a support agent into performing an unrelated action |

More classes are added to the taxonomy with every engagement — see
[Moat](#the-moat) below.

<br/>

## Architecture

- **LLM-based adversarial agent** — tree-search over attack strategies, in the
  spirit of automated jailbreak research (à la GCG / PAIR-style automated
  red-teaming, adapted to tool-chains instead of single-turn prompts)
- **Tool-graph static analysis** — a structural map of tool capabilities, data
  flow, and side effects, built before a single attack is attempted, so
  attacks are targeted rather than brute-forced
- **RL from cross-engagement exploit patterns** — successful exploit chains
  from every engagement feed back into the strategy search, so Talos gets
  measurably sharper with usage, not just with model upgrades
- **Adapter-based harness** — a common interface across agent frameworks
  (LangChain today, native OpenAI/Anthropic function-calling, more later) so
  the same attack engine works regardless of how the target was built

<br/>

## Quickstart

```bash
git clone https://github.com/your-org/talos.git
cd talos
pip install -e .

# Run against a LangChain-based agent
talos-scan --target http://localhost:8000/agent --adapter langchain

# Run against a native function-calling agent
talos-scan --target http://localhost:8001/agent --adapter native
```

Output: a Markdown vulnerability report in `./reports/`, including the
discovered tool graph, every exploit class found, severity scores, and exact
reproduction steps.

> **Note:** all example/target agents ship with simulated side effects only —
> no real payment rails, no real outbound email. Point Talos at your own
> staging agent to get real findings.

<br/>

## Why now

Three curves are crossing at once:

1. **Agent deployment is compounding.** Tool-using agents with real
   permissions — payments, code execution, internal system access — are going
   from "pilot" to "production default" across enterprise software.
2. **The exploit surface is genuinely novel.** Tool-chain vulnerabilities don't
   map cleanly onto the last twenty years of appsec tooling; the industry has
   no default answer yet for "how do we test an agent," the way it long ago
   converged on an answer for "how do we test a web app."
3. **The cost of getting this wrong is asymmetric and public.** A single
   agent-enabled fraud or data-loss incident at a recognizable company sets the
   entire category's adoption timeline back — which means the market for
   "prove this is safe before you ship it" arrives before most vendors expect.

<br/>

## The moat

Talos is built around a compounding data asset: a **proprietary exploit-pattern
database** that grows with every engagement. Each successful attack chain,
across every customer's tool graph, sharpens the strategy search for the next
engagement — a flywheel closer to how detection-engineering vendors compound
than how point-in-time pentest shops operate. The taxonomy in this repo is v0;
the real product is the corpus behind it.

<br/>

## Research

The core methodology — automated red-teaming for tool-using LLM agents,
specifically the tool-graph-aware attack generation approach — is a novel
enough contribution to target a publication venue alongside the product:
USENIX Security, IEEE S&P, or the NeurIPS safety track. If you work in
adversarial ML, automated red-teaming, or agent safety and want to collaborate
on the research track, reach out.

<br/>

## Roadmap

**MVP (4–8 weeks)**
- [x] Tool-graph discovery + static analysis
- [x] Local attack-template engine (~25 templates across 5 exploit classes)
- [x] Dual harness adapters (LangChain + native function-calling)
- [x] Scoring, deduplication, and Markdown reporting
- [ ] LLM-driven attack generation (adaptive tree-search refinement)

**6–12 months**
- [ ] Reinforcement learning from cross-engagement exploit patterns
- [ ] Continuous monitoring product — not just point-in-time audit
- [ ] Expanded exploit taxonomy beyond the initial five classes
- [ ] Push toward an industry certification standard for agent security

<br/>

## Business model

Security-audit SaaS for point-in-time engagements, with a continuous
monitoring subscription for enterprises running agents in production —
because a tool graph that passed a scan in January can fail in June the
moment someone ships a new integration.

<br/>

## Company

Talos exists because the industry is about to learn, the hard way, that
shipping an autonomous agent with real tool access is not the same as shipping
a chatbot. We'd rather you find that out from us, in a report, than from an
incident.

**Status:** pre-seed, MVP in active development.

If you're deploying agents with real tool access — payments, internal data,
outbound communication, code execution — and want to know where your vein is
before someone else finds it, get in touch.

---

<div align="center">
<sub>Talos — built for the agents guarding things that matter.</sub>
</div>
