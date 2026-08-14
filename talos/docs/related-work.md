# Related work / readings

A running bibliography for the Talos research paper. Entries are added as
they're found — see the "how to add a reading" convention at the bottom
if you're picking this up later or handing it to a coding agent.

Each entry: full citation, one-line relevance to Talos, and a category tag
so a literature review section can group them.

---

## Categories

- `prompt-injection` — direct/indirect prompt injection, jailbreaking
- `agent-security` — tool-using / agentic LLM system vulnerabilities
- `red-teaming` — automated adversarial testing methodologies
- `benchmarks` — existing taxonomies, benchmarks, evaluation suites
- `multi-agent` — multi-agent system security, agent-to-agent trust
- `defense` — mitigation, guardrails, policy enforcement techniques

---

## Entries

*(none added yet — paste readings in chat and I'll add them here)*

---

## How to add a reading

Paste a reading in this format in chat, and it'll be appended here, committed, and pushed:

```
ADD READING:
Title: <paper/article title>
Authors: <author list>
Year: <year>
Venue: <conference/journal/preprint, e.g. "arXiv" or "USENIX Security 2024">
Link: <url or DOI>
Category: <one or more of: prompt-injection, agent-security, red-teaming, benchmarks, multi-agent, defense>
Relevance: <one or two sentences on how it connects to Talos specifically —
  e.g. "prior taxonomy Talos-35 v1.0 extends" or "baseline Talos's
  auto-fix loop should be compared against">
```

Partial info is fine (a link and a rough note is enough to start) — this file is meant to be built up incrementally, not filled out perfectly on the first pass.
