"""
Animated exploit replay -- item 10 of the roadmap.

Renders one finding's attack conversation as a self-contained, animated
HTML document: the attack message(s) arriving, the tool call the agent
made, the tool's result, and a final "EXPLOIT CONFIRMED" reveal with the
blast-radius payoff line. Pure presentation on data Talos already fully
has (ReportVariant.messages / .evidence, BlastRadius.summary) -- no new
detection logic, no video/GIF encoding, no external network dependencies
(inline CSS/JS only, no font/CDN links) so the exported file genuinely
works standalone, offline, and can be opened or shared on its own.

Two consumers of the same `render_replay_html()`:
  1. The dashboard embeds it in-place via an <iframe srcdoc="..."> inside
     a finding card's "Replay" toggle (talos/talos/dashboard.py).
  2. `POST /api/replay` returns the identical HTML as a downloadable
     .html file for the "Download replay" button -- same function, same
     output, just served two different ways.
"""

from __future__ import annotations

import html
import json
from typing import Any


def _pick_variant(finding: dict[str, Any]) -> dict[str, Any]:
    variants = finding.get("variants") or []
    if not variants:
        return {}
    for v in variants:
        if v.get("outcome") == "success":
            return v
    return variants[0]


def _esc(value: Any) -> str:
    return html.escape(str(value), quote=True)


def render_replay_html(finding: dict[str, Any]) -> str:
    """`finding` is a plain dict matching ReportFinding.model_dump() (or
    the equivalent JSON already sent to the browser) -- this function has
    no dependency on the pydantic model class itself, so it works equally
    well server-side and from data the dashboard already holds."""
    variant = _pick_variant(finding)
    messages = variant.get("messages") or []
    evidence = variant.get("evidence") or {}
    blast_radius = finding.get("blast_radius") or {}
    severity = str(finding.get("severity", "low")).lower()
    title = _esc(finding.get("title", "Talos finding"))
    exploit_label = _esc(finding.get("exploit_label", ""))
    target_tool = _esc(finding.get("target_tool", ""))
    template_id = _esc(variant.get("template_id", ""))
    payoff = _esc(blast_radius.get("summary") or "Exposure could not be quantified from this run's evidence.")

    severity_colors = {
        "critical": "#e0483f",
        "high": "#e0913f",
        "medium": "#93a865",
        "low": "#5f9c81",
    }
    severity_bg = {
        "critical": "rgba(224, 72, 63, 0.12)",
        "high": "rgba(224, 145, 63, 0.12)",
        "medium": "rgba(147, 168, 101, 0.12)",
        "low": "rgba(95, 156, 129, 0.12)",
    }
    accent = severity_colors.get(severity, "#c9a227")
    accent_bg = severity_bg.get(severity, "rgba(201, 162, 39, 0.12)")

    step_index = 0
    steps_html: list[str] = []

    for message in messages:
        step_index += 1
        steps_html.append(
            f'''
        <div class="step" style="animation-delay: {step_index * 0.9:.1f}s">
          <div class="step-label">Message sent</div>
          <div class="bubble user">{_esc(message)}</div>
        </div>'''
        )

    step_index += 1
    tool_call_json = _esc(json.dumps({k: v for k, v in evidence.items()}, indent=2, default=str)[:1200])
    steps_html.append(
        f'''
        <div class="step" style="animation-delay: {step_index * 0.9:.1f}s">
          <div class="step-label">Tool call -- {target_tool or "unknown tool"}</div>
          <pre class="tool-call">{tool_call_json}</pre>
        </div>'''
    )

    step_index += 1
    steps_html.append(
        f'''
        <div class="step reveal" style="animation-delay: {step_index * 0.9:.1f}s">
          <div class="seal">EXPLOIT CONFIRMED</div>
          <div class="payoff">{payoff}</div>
        </div>'''
    )

    total_delay = (step_index + 1) * 0.9

    return f'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Talos replay -- {title}</title>
<style>
  :root {{
    --ink: #0a0a0c;
    --panel: #131316;
    --panel-2: #0e0e10;
    --hairline: #2a231c;
    --ivory: #f3ead9;
    --muted: #9c9284;
    --gold: #c9a227;
    --accent: {accent};
    --accent-bg: {accent_bg};
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0;
    padding: 32px 20px;
    background: var(--ink);
    color: var(--ivory);
    font-family: ui-monospace, "SFMono-Regular", Menlo, Consolas, monospace;
    -webkit-font-smoothing: antialiased;
  }}
  .case-file {{
    max-width: 640px;
    margin: 0 auto;
  }}
  .header {{
    border-bottom: 1px solid var(--hairline);
    padding-bottom: 16px;
    margin-bottom: 24px;
  }}
  .header .kicker {{
    color: var(--accent);
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.12em;
    margin-bottom: 8px;
  }}
  .header h1 {{
    margin: 0 0 8px;
    font-size: 1.3rem;
  }}
  .header .meta {{
    color: var(--muted);
    font-size: 0.82rem;
  }}
  .step {{
    opacity: 0;
    transform: translateY(8px);
    animation: reveal 0.5s ease forwards;
    margin-bottom: 20px;
  }}
  @keyframes reveal {{
    to {{ opacity: 1; transform: translateY(0); }}
  }}
  .step-label {{
    font-size: 0.72rem;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: var(--muted);
    margin-bottom: 6px;
  }}
  .bubble {{
    background: var(--panel-2);
    border: 1px solid var(--hairline);
    border-radius: 10px;
    padding: 12px 14px;
    font-size: 0.86rem;
    white-space: pre-wrap;
    word-break: break-word;
  }}
  .tool-call {{
    background: #050505;
    border: 1px solid var(--hairline);
    border-radius: 10px;
    padding: 12px 14px;
    font-size: 0.78rem;
    overflow-x: auto;
    margin: 0;
    color: #d8cdb8;
  }}
  .step.reveal {{
    text-align: center;
    padding: 24px 16px;
    border: 1px solid var(--accent);
    border-radius: 14px;
    background: var(--accent-bg);
  }}
  .seal {{
    display: inline-block;
    font-weight: 700;
    letter-spacing: 0.1em;
    color: var(--accent);
    border: 2px solid var(--accent);
    border-radius: 999px;
    padding: 8px 20px;
    margin-bottom: 12px;
    font-size: 0.85rem;
  }}
  .payoff {{
    color: var(--ivory);
    font-size: 0.95rem;
  }}
  .replay-again {{
    display: block;
    margin: 28px auto 0;
    background: transparent;
    color: var(--muted);
    border: 1px solid var(--hairline);
    border-radius: 8px;
    padding: 8px 16px;
    font-family: inherit;
    font-size: 0.78rem;
    cursor: pointer;
  }}
  .replay-again:hover {{ color: var(--ivory); border-color: var(--gold); }}
  .footer {{
    margin-top: 32px;
    padding-top: 16px;
    border-top: 1px solid var(--hairline);
    color: var(--muted);
    font-size: 0.72rem;
    text-align: center;
  }}
</style>
</head>
<body>
  <div class="case-file" id="case-file">
    <div class="header">
      <div class="kicker">Talos exploit replay -- {exploit_label}</div>
      <h1>{title}</h1>
      <div class="meta">Template {template_id or "n/a"} &middot; Severity: {severity.upper()} &middot; Target tool: {target_tool or "n/a"}</div>
    </div>
    <div id="steps">{"".join(steps_html)}</div>
    <button class="replay-again" onclick="replayAnimation()">Replay again</button>
    <div class="footer">Generated by Talos &middot; self-contained, no external dependencies &middot; offline-viewable</div>
  </div>
  <script>
    function replayAnimation() {{
      const steps = document.getElementById("steps");
      const clone = steps.cloneNode(true);
      steps.parentNode.replaceChild(clone, steps);
    }}
  </script>
</body>
</html>'''
