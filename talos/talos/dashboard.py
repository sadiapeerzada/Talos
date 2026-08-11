"""FastAPI dashboard for running Talos scans locally."""

from __future__ import annotations

import argparse
import json
import threading
import time
import urllib.request
import webbrowser
from typing import Iterator

import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, PlainTextResponse, StreamingResponse
from pydantic import BaseModel, Field

from talos.learning import LearningStore, LearningSummary
from talos.monitoring import AlertRecord, MonitorConfig, MonitorSnapshot, MonitoringManager
from talos.replay import render_replay_html
from talos.reporting.report import ReportFinding, ScanReport, render_markdown_report
from talos.scan_service import (
    ADAPTERS,
    DEFAULT_ATTACKER_EMAIL,
    DEFAULT_GENERATION_STRATEGY,
    DEFAULT_POISONED_ORDER_IDS,
    DEFAULT_SEED_ORDER_IDS,
    GENERATION_STRATEGIES,
    iter_scan_progress,
)

app = FastAPI(title="Talos Dashboard")
monitoring_manager = MonitoringManager()
learning_store = LearningStore()


class ScanRequest(BaseModel):
    target: str
    adapter: str
    attacker_email: str = DEFAULT_ATTACKER_EMAIL
    seed_order_ids: list[str] = Field(default_factory=lambda: list(DEFAULT_SEED_ORDER_IDS))
    poisoned_order_ids: list[str] = Field(default_factory=lambda: list(DEFAULT_POISONED_ORDER_IDS))
    repro_runs: int = 3
    strategy: str = DEFAULT_GENERATION_STRATEGY
    attack_model: str = "claude-sonnet-4-5"


class MonitorRequest(ScanRequest):
    interval_seconds: float = 60.0
    max_runs: int | None = None


def _dashboard_html() -> str:
    options = "\n".join(
        f'<option value="{name}"{" selected" if index == 0 else ""}>{name}</option>'
        for index, name in enumerate(ADAPTERS)
    )
    defaults = {
        "attacker_email": DEFAULT_ATTACKER_EMAIL,
        "seed_order_ids": ",".join(DEFAULT_SEED_ORDER_IDS),
        "poisoned_order_ids": ",".join(DEFAULT_POISONED_ORDER_IDS),
        "strategy": DEFAULT_GENERATION_STRATEGY,
        "attack_model": "claude-sonnet-4-5",
    }
    strategy_options = "\n".join(
        f'<option value="{name}"{" selected" if name == defaults["strategy"] else ""}>{name}</option>'
        for name in GENERATION_STRATEGIES
    )
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Talos Dashboard</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Fraunces:opsz,wght@9..144,500;9..144,600;9..144,700&family=IBM+Plex+Sans:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500;600&display=swap" rel="stylesheet">
  <style>
    /*
      Design tokens -- "assay mark" direction: a private vault ledger, not a
      typical dark-mode dev tool. Black stands in for the vault, gold for
      the seal stamped on a verified finding. Severity colors are pulled
      deliberately AWAY from gold/amber (brass-green medium, patina-green
      low) so a Medium finding never visually reads as "part of the theme"
      the way a conventional amber/yellow severity color would on a gold
      accent page -- see the write-up in the Medium-severity fix commit.

      Color -- --ink #0a0a0c, --panel #131316, --hairline #2a231c (warm
               bronze, not cool gray -- keeps borders in the gold family),
               --gold #c9a227 (antique/museum gold, not neon), --ivory
               #f3ead9 (warm parchment text, not stark white).
      Type   -- Fraunces (display/headline serif, used sparingly for the
               hero number and section titles) + IBM Plex Sans (body/UI) +
               IBM Plex Mono (technical/data fields: URLs, JSON, dollar
               amounts, evidence).
      Layout -- unchanged grid/panel structure from the working dashboard;
               this pass is a full re-skin, not a re-architecture.
      Signature -- the Risk score card is rendered as a struck gold seal: a
               conic-gradient ring that fills clockwise with the risk
               score, the number set in Fraunces at its center. Everything
               else stays quiet so this one element carries the "premium"
               read.
    */
    :root {{
      color-scheme: dark;
      --ink: #0a0a0c;
      --ink-grid: #0c0c0e;
      --panel: #131316;
      --panel-2: #0e0e10;
      --hairline: #2a231c;
      --hairline-soft: #1c1815;
      --ivory: #f3ead9;
      --muted: #9c9284;
      --gold: #c9a227;
      --gold-bright: #e8c766;
      --gold-dim: rgba(201, 162, 39, 0.14);
      --gold-line: rgba(201, 162, 39, 0.38);
      --critical: #e0483f;
      --critical-bg: rgba(224, 72, 63, 0.14);
      --high: #e0913f;
      --high-bg: rgba(224, 145, 63, 0.14);
      --medium: #93a865;
      --medium-bg: rgba(147, 168, 101, 0.14);
      --low: #5f9c81;
      --low-bg: rgba(95, 156, 129, 0.14);
      --mono: "IBM Plex Mono", "SFMono-Regular", ui-monospace, Menlo, Consolas, monospace;
      --sans: "IBM Plex Sans", -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      --serif: "Fraunces", "Iowan Old Style", Georgia, serif;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: var(--sans);
      background:
        radial-gradient(1100px 550px at 12% -8%, rgba(201,162,39,0.06), transparent),
        radial-gradient(800px 460px at 105% 4%, rgba(201,162,39,0.04), transparent),
        var(--ink);
      color: var(--ivory);
      -webkit-font-smoothing: antialiased;
    }}
    .page {{
      max-width: 1100px;
      margin: 0 auto;
      padding: 40px 20px 64px;
    }}
    .top-row {{
      display: flex;
      align-items: baseline;
      justify-content: space-between;
      gap: 12px;
      flex-wrap: wrap;
    }}
    h1 {{
      margin: 0 0 6px;
      font-family: var(--serif);
      font-weight: 600;
      font-size: 2.1rem;
      letter-spacing: -0.01em;
    }}
    h1 .dot {{
      display: inline-block;
      width: 9px;
      height: 9px;
      border-radius: 50%;
      background: var(--gold);
      box-shadow: 0 0 14px 2px var(--gold-dim);
      margin-right: 10px;
      vertical-align: middle;
    }}
    .subtitle {{ margin: 0 0 26px; color: var(--muted); font-size: 0.96rem; }}
    .badge-live {{
      font-family: var(--mono);
      font-size: 0.7rem;
      letter-spacing: 0.12em;
      color: var(--gold-bright);
      background: var(--gold-dim);
      border: 1px solid var(--gold-line);
      border-radius: 999px;
      padding: 5px 12px;
      text-transform: uppercase;
    }}
    .panel {{
      background: var(--panel);
      border: 1px solid var(--hairline);
      border-radius: 14px;
      padding: 22px;
      margin-bottom: 18px;
      box-shadow: 0 1px 0 rgba(255,255,255,0.015) inset;
    }}
    .panel-title {{
      margin: 0 0 4px;
      font-family: var(--serif);
      font-size: 1.15rem;
      font-weight: 600;
      display: flex;
      align-items: center;
      gap: 10px;
    }}
    .panel-subtitle {{ margin: 0 0 16px; color: var(--muted); font-size: 0.88rem; }}
    .section-label {{
      font-family: var(--mono);
      font-size: 0.72rem;
      color: var(--gold);
      text-transform: uppercase;
      letter-spacing: 0.1em;
      margin: 0 0 10px;
    }}
    form {{
      display: grid;
      grid-template-columns: minmax(0, 1.8fr) minmax(180px, 0.7fr) auto;
      gap: 12px;
      align-items: end;
    }}
    .field {{
      display: flex;
      flex-direction: column;
      gap: 7px;
    }}
    .field-hint {{
      font-size: 0.78rem;
      color: var(--muted);
      margin-top: -2px;
    }}
    label {{
      font-size: 0.86rem;
      color: var(--muted);
      font-weight: 500;
    }}
    input, select, button, textarea {{
      width: 100%;
      padding: 11px 13px;
      border: 1px solid var(--hairline);
      border-radius: 9px;
      font: inherit;
      background: var(--panel-2);
      color: var(--ivory);
    }}
    input, textarea {{ font-family: var(--mono); font-size: 0.87rem; }}
    input::placeholder, textarea::placeholder {{ color: #59503f; }}
    input:focus, select:focus, textarea:focus {{
      outline: none;
      border-color: var(--gold-line);
      box-shadow: 0 0 0 3px var(--gold-dim);
    }}
    textarea {{ min-height: 76px; resize: vertical; }}
    button {{
      width: auto;
      min-width: 140px;
      background: linear-gradient(180deg, var(--gold-bright), var(--gold));
      color: #17130a;
      font-weight: 700;
      font-family: var(--sans);
      cursor: pointer;
      border-color: var(--gold);
      transition: transform 0.08s ease, box-shadow 0.18s ease, filter 0.18s ease;
    }}
    button:hover:not(:disabled) {{
      box-shadow: 0 0 0 4px var(--gold-dim), 0 6px 18px -6px rgba(201,162,39,0.55);
      filter: brightness(1.04);
    }}
    button:active:not(:disabled) {{ transform: translateY(1px); }}
    button:disabled {{ opacity: 0.45; cursor: wait; filter: none; box-shadow: none; }}
    .button-secondary {{
      background: var(--panel-2);
      color: var(--ivory);
      border-color: var(--hairline);
      font-weight: 600;
    }}
    .button-secondary:hover:not(:disabled) {{
      box-shadow: 0 0 0 3px var(--hairline-soft);
      filter: none;
    }}
    details {{ margin-top: 16px; }}
    details summary {{
      cursor: pointer;
      color: var(--muted);
      user-select: none;
      font-size: 0.9rem;
    }}
    details summary:hover {{ color: var(--gold-bright); }}
    .advanced-groups {{
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 16px;
      margin-top: 16px;
    }}
    .advanced-group {{
      border: 1px solid var(--hairline-soft);
      border-radius: 12px;
      padding: 14px;
      background: var(--panel-2);
    }}
    .advanced-group .group-title {{
      font-family: var(--mono);
      font-size: 0.72rem;
      color: var(--muted);
      text-transform: uppercase;
      letter-spacing: 0.08em;
      margin: 0 0 12px;
    }}
    .advanced-group .field {{ margin-bottom: 12px; }}
    .advanced-group .field:last-child {{ margin-bottom: 0; }}

    /* Step progress tracker */
    .stepper {{
      display: flex;
      align-items: center;
      gap: 0;
      margin-bottom: 20px;
      flex-wrap: wrap;
    }}
    .step {{
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 6px 12px 6px 6px;
      border-radius: 999px;
      background: var(--panel-2);
      border: 1px solid var(--hairline);
      font-size: 0.8rem;
      color: var(--muted);
      transition: all 0.25s ease;
    }}
    .step .step-dot {{
      width: 20px;
      height: 20px;
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 0.7rem;
      font-weight: 700;
      background: var(--hairline-soft);
      color: var(--muted);
      flex-shrink: 0;
    }}
    .step.done {{ color: var(--ivory); border-color: var(--gold-line); background: var(--gold-dim); }}
    .step.done .step-dot {{ background: var(--gold); color: #17130a; }}
    .step.active {{ color: var(--ivory); border-color: var(--gold); }}
    .step.active .step-dot {{ background: var(--gold); color: #17130a; animation: pulse 1.4s ease-in-out infinite; }}
    .step-connector {{ width: 18px; height: 1px; background: var(--hairline); flex-shrink: 0; }}
    @keyframes pulse {{
      0%, 100% {{ box-shadow: 0 0 0 0 var(--gold-dim); }}
      50% {{ box-shadow: 0 0 0 6px transparent; }}
    }}

    .status-row {{
      display: flex;
      justify-content: space-between;
      gap: 12px;
      align-items: center;
      flex-wrap: wrap;
      margin-bottom: 18px;
    }}
    .status-text {{ font-weight: 600; }}
    .status-subtext {{ color: var(--muted); font-size: 0.9rem; margin-top: 4px; }}

    /* Hero stat row -- the risk-score card carries the signature gauge */
    .hero-stats {{
      display: grid;
      grid-template-columns: 1.4fr 1fr 1fr 1fr;
      gap: 14px;
      margin-bottom: 4px;
    }}
    .hero-stat {{
      border-radius: 14px;
      padding: 18px;
      border: 1px solid var(--hairline);
      background: var(--panel-2);
      position: relative;
      overflow: hidden;
    }}
    .hero-stat.wow {{
      background: linear-gradient(135deg, rgba(201,162,39,0.10), rgba(201,162,39,0.01));
      border-color: var(--gold-line);
      display: flex;
      align-items: center;
      gap: 16px;
    }}
    .hero-stat-label {{
      color: var(--muted);
      font-size: 0.76rem;
      text-transform: uppercase;
      letter-spacing: 0.07em;
      margin-bottom: 8px;
      font-family: var(--mono);
    }}
    .hero-stat-value {{
      font-size: 2.05rem;
      font-weight: 700;
      letter-spacing: -0.02em;
      font-family: var(--serif);
    }}
    .hero-stat-value.crit {{ color: var(--critical); }}
    .hero-stat-value.high {{ color: var(--high); }}
    .hero-stat-sub {{ color: var(--muted); font-size: 0.78rem; margin-top: 4px; }}

    /* Signature element: gold seal / gauge ring around the risk score,
       filled clockwise via a conic-gradient driven by --risk-pct (set in
       JS as a percentage 0-100). */
    .risk-gauge {{
      --risk-pct: 0%;
      width: 76px;
      height: 76px;
      border-radius: 50%;
      flex-shrink: 0;
      background: conic-gradient(var(--gold) var(--risk-pct), var(--hairline-soft) var(--risk-pct));
      display: flex;
      align-items: center;
      justify-content: center;
      transition: background 0.6s ease;
    }}
    .risk-gauge-inner {{
      width: 60px;
      height: 60px;
      border-radius: 50%;
      background: var(--panel);
      display: flex;
      align-items: center;
      justify-content: center;
      box-shadow: inset 0 0 0 1px var(--hairline);
    }}
    .hero-stat.wow .hero-stat-copy {{ flex: 1; min-width: 0; }}

    .stats {{
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 12px;
    }}
    .stat {{
      background: var(--panel-2);
      border: 1px solid var(--hairline);
      border-radius: 12px;
      padding: 14px 16px;
    }}
    .stat-label {{ color: var(--muted); font-size: 0.8rem; margin-bottom: 6px; font-family: var(--mono); }}
    .stat-value {{ font-size: 1.5rem; font-weight: 700; letter-spacing: -0.02em; font-family: var(--serif); }}

    .findings-empty {{ color: var(--muted); margin: 0; }}
    .skeleton {{
      display: flex;
      flex-direction: column;
      gap: 10px;
    }}
    .skeleton-row {{
      height: 56px;
      border-radius: 12px;
      background: linear-gradient(90deg, var(--panel-2) 0%, var(--hairline-soft) 50%, var(--panel-2) 100%);
      background-size: 200% 100%;
      animation: shimmer 1.4s ease-in-out infinite;
    }}
    @keyframes shimmer {{
      0% {{ background-position: 200% 0; }}
      100% {{ background-position: -200% 0; }}
    }}

    .severity-group {{ margin-bottom: 18px; }}
    .severity-group:last-child {{ margin-bottom: 0; }}
    .severity-group-header {{
      display: flex;
      align-items: center;
      gap: 8px;
      margin: 0 0 10px;
      font-size: 0.85rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      font-family: var(--mono);
    }}
    .severity-group-count {{
      font-family: var(--mono);
      font-size: 0.75rem;
      padding: 2px 8px;
      border-radius: 999px;
      font-weight: 700;
    }}
    .findings {{
      display: flex;
      flex-direction: column;
      gap: 10px;
    }}
    .finding {{
      border: 1px solid var(--hairline);
      border-radius: 14px;
      background: var(--panel-2);
      overflow: hidden;
      animation: slideIn 0.35s ease;
    }}
    @keyframes slideIn {{
      from {{ opacity: 0; transform: translateY(-6px); }}
      to {{ opacity: 1; transform: translateY(0); }}
    }}
    .finding summary {{
      list-style: none;
      cursor: pointer;
      padding: 14px 16px;
    }}
    .finding summary::-webkit-details-marker {{ display: none; }}
    .finding-header {{
      display: flex;
      justify-content: space-between;
      gap: 12px;
      align-items: flex-start;
    }}
    .finding-title {{ font-weight: 700; margin: 0 0 4px; font-size: 0.96rem; font-family: var(--sans); }}
    .finding-summary {{ margin: 0; color: var(--muted); font-size: 0.88rem; }}
    .badge {{
      display: inline-flex;
      align-items: center;
      gap: 5px;
      justify-content: center;
      min-width: 74px;
      padding: 5px 10px;
      border-radius: 999px;
      font-size: 0.72rem;
      font-weight: 800;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      font-family: var(--mono);
      flex-shrink: 0;
      white-space: nowrap;
    }}
    .badge::before {{ content: ""; width: 6px; height: 6px; border-radius: 50%; display: inline-block; }}
    .badge-critical {{ color: var(--critical); background: var(--critical-bg); border: 1px solid rgba(224,72,63,0.35); }}
    .badge-critical::before {{ background: var(--critical); }}
    .badge-high {{ color: var(--high); background: var(--high-bg); border: 1px solid rgba(224,145,63,0.35); }}
    .badge-high::before {{ background: var(--high); }}
    .badge-medium {{ color: var(--medium); background: var(--medium-bg); border: 1px solid rgba(147,168,101,0.4); }}
    .badge-medium::before {{ background: var(--medium); }}
    .badge-low {{ color: var(--low); background: var(--low-bg); border: 1px solid rgba(95,156,129,0.4); }}
    .badge-low::before {{ background: var(--low); }}
    .finding-body {{ padding: 0 16px 16px; border-top: 1px solid var(--hairline-soft); }}
    .blast-radius {{
      margin: 12px 0 0;
      padding: 8px 12px;
      border-radius: 8px;
      background: var(--gold-dim);
      border: 1px solid var(--gold-line);
      color: var(--gold-bright);
      font-size: 0.85rem;
      font-family: var(--mono);
    }}
    .replay-controls {{
      display: flex;
      gap: 10px;
      margin-top: 14px;
      flex-wrap: wrap;
    }}
    .replay-controls button {{
      width: auto;
      min-width: 0;
      padding: 8px 14px;
      font-size: 0.8rem;
    }}
    .replay-frame-wrap {{
      margin-top: 14px;
      border: 1px solid var(--gold-line);
      border-radius: 12px;
      overflow: hidden;
      box-shadow: 0 0 0 3px var(--gold-dim);
    }}
    .replay-frame {{
      width: 100%;
      height: 480px;
      border: 0;
      display: block;
      background: var(--ink);
    }}
    .meta {{
      display: flex;
      gap: 16px;
      flex-wrap: wrap;
      color: var(--muted);
      font-size: 0.85rem;
      margin: 12px 0;
      font-family: var(--mono);
    }}
    .variant {{
      border: 1px solid var(--hairline-soft);
      border-radius: 10px;
      padding: 12px;
      margin-top: 10px;
      background: var(--ink-grid);
    }}
    .variant h4 {{ margin: 0 0 8px; font-size: 0.9rem; font-family: var(--mono); font-weight: 600; }}
    ol {{ margin: 8px 0 0 20px; padding: 0; font-size: 0.88rem; }}
    pre {{
      margin: 8px 0 0;
      padding: 12px;
      border-radius: 10px;
      background: #050505;
      color: #d8cdb8;
      overflow: auto;
      font-size: 0.8rem;
      border: 1px solid var(--hairline-soft);
    }}
    .hidden {{ display: none; }}

    .monitor-actions {{ display: flex; gap: 12px; flex-wrap: wrap; margin-top: 14px; }}
    .monitor-actions button {{ width: auto; }}
    .history-list {{ display: flex; flex-direction: column; gap: 12px; margin-top: 14px; }}
    .history-card {{ border: 1px solid var(--hairline); border-radius: 12px; background: var(--panel-2); padding: 14px; }}
    .history-card h3 {{ margin: 0 0 6px; font-size: 0.95rem; font-family: var(--mono); }}
    .history-meta {{ color: var(--muted); font-size: 0.85rem; display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 10px; font-family: var(--mono); }}
    .monitor-empty {{ color: var(--muted); margin: 0; }}

    .alerts-list {{ display: flex; flex-direction: column; gap: 12px; margin-top: 14px; }}
    .alert-card {{ border: 1px solid rgba(224,145,63,0.35); border-radius: 12px; background: var(--high-bg); padding: 14px; }}
    .alert-card h3 {{ margin: 0 0 6px; font-size: 0.95rem; font-family: var(--mono); color: var(--high); }}
    .learning-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 14px; margin-top: 14px; }}
    .learning-card {{ border: 1px solid var(--hairline); border-radius: 12px; background: var(--panel-2); padding: 14px; }}
    .learning-card h3 {{ margin: 0 0 8px; font-size: 0.88rem; font-family: var(--mono); color: var(--gold-bright); text-transform: uppercase; letter-spacing: 0.05em; }}
    .learning-card ul {{ margin: 0; padding-left: 18px; font-size: 0.85rem; color: var(--muted); }}

    /* Before/after run comparison */
    .compare-table {{ width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 0.88rem; }}
    .compare-table th, .compare-table td {{ text-align: left; padding: 10px 12px; border-bottom: 1px solid var(--hairline-soft); }}
    .compare-table th {{ color: var(--muted); font-family: var(--mono); font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; }}
    .compare-table td.label-cell {{ font-weight: 700; }}
    .delta-down {{ color: var(--low); font-family: var(--mono); }}
    .delta-flat {{ color: var(--muted); font-family: var(--mono); }}
    .delta-up {{ color: var(--critical); font-family: var(--mono); }}
    .runs-empty {{ color: var(--muted); font-size: 0.88rem; margin-top: 10px; }}

    @media (max-width: 820px) {{
      form, .stats, .hero-stats, .advanced-groups, .learning-grid {{ grid-template-columns: 1fr; }}
      button {{ width: 100%; }}
    }}
  </style>
</head>
<body>
  <div class="page">
    <div class="top-row">
      <h1><span class="dot"></span>Talos Dashboard</h1>
      <span class="badge-live">live scan engine</span>
    </div>
    <p class="subtitle">Run the existing Talos scan engine locally and watch findings land in real time.</p>

    <section class="panel">
      <div class="panel-title">Target</div>
      <form id="scan-form">
        <div class="field">
          <label for="target">Target URL</label>
          <input id="target" name="target" type="url" placeholder="http://127.0.0.1:8001/agent" required>
        </div>
        <div class="field">
          <label for="adapter">Adapter</label>
          <select id="adapter" name="adapter">{options}</select>
        </div>
        <button id="run-button" type="submit">Run scan</button>
      </form>
      <div class="field" style="margin-top: 12px; max-width: 320px;">
        <label for="run_label">Run label <span class="field-hint">(optional -- tag this run, e.g. "before" / "after")</span></label>
        <input id="run_label" name="run_label" type="text" placeholder="e.g. before-hardening">
      </div>

      <details>
        <summary>Advanced options</summary>
        <div class="advanced-groups">
          <div class="advanced-group">
            <p class="group-title">Target configuration</p>
            <div class="field">
              <label for="attacker_email">Attacker email</label>
              <input id="attacker_email" name="attacker_email" type="email" value="{defaults["attacker_email"]}">
              <div class="field-hint">Destination Talos uses for exfiltration/injection probes.</div>
            </div>
            <div class="field">
              <label for="seed_order_ids">Seed order IDs</label>
              <input id="seed_order_ids" name="seed_order_ids" type="text" value="{defaults["seed_order_ids"]}">
              <div class="field-hint">Known-valid order IDs on the target, comma-separated.</div>
            </div>
            <div class="field">
              <label for="poisoned_order_ids">Poisoned order IDs</label>
              <input id="poisoned_order_ids" name="poisoned_order_ids" type="text" value="{defaults["poisoned_order_ids"]}">
              <div class="field-hint">Order IDs with embedded injection payloads to exercise.</div>
            </div>
          </div>
          <div class="advanced-group">
            <p class="group-title">Attack configuration</p>
            <div class="field">
              <label for="strategy">Attack strategy</label>
              <select id="strategy" name="strategy">{strategy_options}</select>
              <div class="field-hint">"template" = deterministic; "adaptive" = LLM-refined attacks.</div>
            </div>
            <div class="field">
              <label for="attack_model">Adaptive model</label>
              <input id="attack_model" name="attack_model" type="text" value="{defaults["attack_model"]}">
              <div class="field-hint">Used only when strategy is "adaptive". Needs ANTHROPIC_API_KEY.</div>
            </div>
          </div>
        </div>
      </details>
    </section>

    <section class="panel">
      <div class="stepper" id="stepper">
        <div class="step" data-step="connected"><span class="step-dot">1</span>Connect</div>
        <div class="step-connector"></div>
        <div class="step" data-step="tools_discovered"><span class="step-dot">2</span>Discover tools</div>
        <div class="step-connector"></div>
        <div class="step" data-step="attacks_generated"><span class="step-dot">3</span>Generate attacks</div>
        <div class="step-connector"></div>
        <div class="step" data-step="executing"><span class="step-dot">4</span>Execute</div>
        <div class="step-connector"></div>
        <div class="step" data-step="completed"><span class="step-dot">5</span>Score</div>
      </div>
      <div class="status-row">
        <div>
          <div id="status-text" class="status-text">Ready to scan.</div>
          <div id="status-subtext" class="status-subtext">Progress updates will appear here as Talos discovers tools and runs attacks.</div>
        </div>
      </div>
      <div class="hero-stats">
        <div class="hero-stat wow">
          <div class="risk-gauge" id="risk-gauge">
            <div class="risk-gauge-inner"></div>
          </div>
          <div class="hero-stat-copy">
            <div class="hero-stat-label">Risk score</div>
            <div id="hero-risk" class="hero-stat-value">0<span style="font-size: 1rem; color: var(--muted);">/100</span></div>
            <div class="hero-stat-sub" id="hero-risk-sub">no scan run yet</div>
          </div>
        </div>
        <div class="hero-stat">
          <div class="hero-stat-label">Total findings</div>
          <div id="hero-total" class="hero-stat-value">0</div>
        </div>
        <div class="hero-stat">
          <div class="hero-stat-label">Tools found</div>
          <div id="tools-found" class="hero-stat-value">0</div>
        </div>
        <div class="hero-stat">
          <div class="hero-stat-label">Attacks run</div>
          <div id="attacks-run" class="hero-stat-value">0/0</div>
        </div>
      </div>
      <div class="stats" style="margin-top: 14px;">
        <div class="stat">
          <div class="stat-label">Critical</div>
          <div id="critical-count" class="stat-value" style="color: var(--critical);">0</div>
        </div>
        <div class="stat">
          <div class="stat-label">High</div>
          <div id="high-count" class="stat-value" style="color: var(--high);">0</div>
        </div>
        <div class="stat">
          <div class="stat-label">Medium</div>
          <div id="medium-count" class="stat-value" style="color: var(--medium);">0</div>
        </div>
        <div class="stat">
          <div class="stat-label">Low</div>
          <div id="low-count" class="stat-value" style="color: var(--low);">0</div>
        </div>
      </div>
    </section>

    <section class="panel">
      <div class="panel-title" style="display: flex; justify-content: space-between; align-items: center;">
        <span>Findings</span>
        <button id="export-report-button" type="button" class="button-secondary" style="width: auto; min-width: 0; padding: 8px 14px; font-size: 0.82rem;" disabled>Export report (.md)</button>
      </div>
      <p id="findings-empty" class="findings-empty">No findings yet. Run a scan to populate this list.</p>
      <div id="findings-skeleton" class="skeleton hidden">
        <div class="skeleton-row"></div>
        <div class="skeleton-row"></div>
        <div class="skeleton-row"></div>
      </div>
      <div id="findings" class="findings hidden"></div>
    </section>

    <section class="panel">
      <div class="panel-title">Before / after comparison</div>
      <p class="panel-subtitle">Runs are grouped by the label you gave them above. Run the same scan twice -- once against a vulnerable target, once against a hardened one -- with different labels to compare.</p>
      <div id="runs-empty" class="runs-empty">No labeled runs yet. Give a run a label and run a scan to start tracking it here.</div>
      <table id="runs-table" class="compare-table hidden">
        <thead>
          <tr><th>Label</th><th>Target</th><th>Risk</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Total</th></tr>
        </thead>
        <tbody id="runs-tbody"></tbody>
      </table>
    </section>

    <section class="panel">
      <div class="panel-title">Continuous monitoring</div>
      <p class="panel-subtitle">Re-run full scans on a timer and keep a live history of results.</p>
      <div class="advanced-groups" style="margin-top: 0;">
        <div class="advanced-group">
          <p class="group-title">Schedule</p>
          <div class="field">
            <label for="monitor_interval_seconds">Interval (seconds)</label>
            <input id="monitor_interval_seconds" name="monitor_interval_seconds" type="number" min="1" step="1" value="30">
          </div>
          <div class="field">
            <label for="monitor_max_runs">Max runs (optional)</label>
            <input id="monitor_max_runs" name="monitor_max_runs" type="number" min="1" step="1" placeholder="Leave blank for continuous">
          </div>
        </div>
      </div>
      <div class="monitor-actions">
        <button id="start-monitor-button" type="button">Start monitoring</button>
        <button id="stop-monitor-button" type="button" class="button-secondary" disabled>Stop monitoring</button>
      </div>
      <div style="margin-top: 16px;">
        <div id="monitor-status-text" class="status-text">No active monitor.</div>
        <div id="monitor-status-subtext" class="status-subtext">Start a recurring scan to track the target over time.</div>
      </div>
      <div id="monitor-history-empty" class="monitor-empty" style="margin-top: 16px;">No monitoring history yet.</div>
      <div id="monitor-history" class="history-list hidden"></div>
    </section>

    <section class="panel">
      <h2 style="margin: 0 0 14px;">Recent alerts</h2>
      <p id="alerts-empty" class="monitor-empty">No alerts yet.</p>
      <div id="alerts-list" class="alerts-list hidden"></div>
    </section>

    <section class="panel">
      <h2 style="margin: 0 0 14px;">Cross-engagement learning</h2>
      <p class="subtitle" style="margin: 0 0 16px;">Talos keeps local memory of what has worked across runs and uses it to prioritize future attacks.</p>
      <div id="learning-summary" class="learning-grid hidden"></div>
      <p id="learning-empty" class="monitor-empty">No learning data yet.</p>
    </section>
  </div>

  <script>
    const form = document.getElementById("scan-form");
    const runButton = document.getElementById("run-button");
    const stepper = document.getElementById("stepper");
    const statusText = document.getElementById("status-text");
    const statusSubtext = document.getElementById("status-subtext");
    const toolsFound = document.getElementById("tools-found");
    const attacksRun = document.getElementById("attacks-run");
    const heroRisk = document.getElementById("hero-risk");
    const heroRiskSub = document.getElementById("hero-risk-sub");
    const riskGauge = document.getElementById("risk-gauge");
    const heroTotal = document.getElementById("hero-total");
    const exportReportButton = document.getElementById("export-report-button");
    const criticalCount = document.getElementById("critical-count");
    const highCount = document.getElementById("high-count");
    const mediumCount = document.getElementById("medium-count");
    const lowCount = document.getElementById("low-count");
    const findingsContainer = document.getElementById("findings");
    const findingsEmpty = document.getElementById("findings-empty");
    const findingsSkeleton = document.getElementById("findings-skeleton");
    const runsEmpty = document.getElementById("runs-empty");
    const runsTable = document.getElementById("runs-table");
    const runsTbody = document.getElementById("runs-tbody");
    const startMonitorButton = document.getElementById("start-monitor-button");
    const stopMonitorButton = document.getElementById("stop-monitor-button");
    const monitorStatusText = document.getElementById("monitor-status-text");
    const monitorStatusSubtext = document.getElementById("monitor-status-subtext");
    const monitorHistory = document.getElementById("monitor-history");
    const monitorHistoryEmpty = document.getElementById("monitor-history-empty");
    const alertsEmpty = document.getElementById("alerts-empty");
    const alertsList = document.getElementById("alerts-list");
    const learningSummary = document.getElementById("learning-summary");
    const learningEmpty = document.getElementById("learning-empty");
    let activeMonitorId = null;
    let monitorPollTimer = null;

    // Client-side labeled-run history for the before/after comparison table.
    // Kept in memory only (per Talos's no-browser-storage constraint) --
    // it resets on page reload, which is fine for a live demo session.
    const labeledRuns = [];

    function parseList(value) {{
      return value.split(",").map((item) => item.trim()).filter(Boolean);
    }}

    function escapeHtml(value) {{
      return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#39;");
    }}

    function setStepper(eventType) {{
      const order = ["connected", "tools_discovered", "attacks_generated", "executing", "completed"];
      let reachedIndex = order.indexOf(eventType);
      if (eventType === "attack_scored") reachedIndex = order.indexOf("executing");
      if (reachedIndex === -1) return;
      [...stepper.querySelectorAll(".step")].forEach((el, i) => {{
        el.classList.remove("done", "active");
        if (i < reachedIndex) el.classList.add("done");
        else if (i === reachedIndex) el.classList.add("active");
      }});
    }}

    function resetStepper() {{
      [...stepper.querySelectorAll(".step")].forEach((el) => el.classList.remove("done", "active"));
    }}

    function severityCounts(report) {{
      const counts = {{ critical: 0, high: 0, medium: 0, low: 0 }};
      for (const f of (report?.findings || [])) {{
        if (counts[f.severity] !== undefined) counts[f.severity] += 1;
      }}
      return counts;
    }}

    function setStats(stats, report) {{
      if (!stats) return;
      toolsFound.textContent = String(stats.tools_found ?? 0);
      attacksRun.textContent = `${{stats.attacks_run ?? 0}}/${{stats.attacks_total ?? 0}}`;
      const counts = report ? severityCounts(report) : {{
        critical: stats.critical ?? 0, high: stats.high ?? 0, medium: stats.medium ?? 0, low: stats.low ?? 0
      }};
      criticalCount.textContent = String(counts.critical ?? stats.critical ?? 0);
      highCount.textContent = String(counts.high ?? stats.high ?? 0);
      mediumCount.textContent = String(counts.medium ?? 0);
      lowCount.textContent = String(counts.low ?? 0);
      const findingsTotal = (report?.findings || []).length;
      heroTotal.textContent = String(findingsTotal);

      const risk = report?.stats?.risk_score ?? stats.risk_score ?? 0;
      heroRisk.innerHTML = `${{risk}}<span style="font-size: 1rem; color: var(--muted);">/100</span>`;
      riskGauge.style.setProperty("--risk-pct", `${{risk}}%`);
      heroRisk.className = "hero-stat-value" + (risk >= 60 ? " crit" : risk >= 25 ? " high" : "");
      heroRiskSub.textContent = findingsTotal
        ? `${{counts.critical || 0}} critical, ${{counts.high || 0}} high`
        : "no findings yet";
    }}

    function badgeClass(severity) {{
      return `badge badge-${{severity || "low"}}`;
    }}

    function collectScanPayload() {{
      return {{
        target: document.getElementById("target").value.trim(),
        adapter: document.getElementById("adapter").value,
        attacker_email: document.getElementById("attacker_email").value.trim(),
        seed_order_ids: parseList(document.getElementById("seed_order_ids").value),
        poisoned_order_ids: parseList(document.getElementById("poisoned_order_ids").value),
        strategy: document.getElementById("strategy").value,
        attack_model: document.getElementById("attack_model").value.trim()
      }};
    }}

    const SEVERITY_META = {{
      critical: {{ label: "Critical", order: 4 }},
      high: {{ label: "High", order: 3 }},
      medium: {{ label: "Medium", order: 2 }},
      low: {{ label: "Low", order: 1 }}
    }};

    function renderVariant(variant) {{
      const steps = variant.messages.map((message) => `<li><code>${{escapeHtml(message)}}</code></li>`).join("");
      const evidence = escapeHtml(JSON.stringify(variant.evidence, null, 2));
      return `
        <div class="variant">
          <h4>${{escapeHtml(variant.template_id)}} -- ${{escapeHtml(variant.name)}} (${{escapeHtml(variant.outcome)}})</h4>
          <div><strong>Reproduction steps</strong></div>
          <ol>${{steps}}</ol>
          <div style="margin-top: 10px;"><strong>Evidence</strong></div>
          <pre>${{evidence}}</pre>
        </div>
      `;
    }}

    function renderFindingCard(finding) {{
      const variants = finding.variants.map(renderVariant).join("");
      return `
        <details class="finding">
          <summary>
            <div class="finding-header">
              <div>
                <p class="finding-title">${{escapeHtml(finding.title)}}</p>
                <p class="finding-summary">${{escapeHtml(finding.summary)}}</p>
              </div>
              <span class="${{badgeClass(finding.severity)}}">${{escapeHtml(finding.severity)}}</span>
            </div>
          </summary>
          <div class="finding-body">
            <div class="meta">
              <span>tool: <strong>${{escapeHtml(finding.target_tool)}}</strong></span>
              <span>class: <strong>${{escapeHtml(finding.exploit_label)}}</strong></span>
              <span>repro: <strong>${{Math.round((finding.reproducibility || 0) * 100)}}%</strong></span>
            </div>
            ${{finding.blast_radius ? `<p class="blast-radius">${{escapeHtml(finding.blast_radius.summary)}}</p>` : ""}}
            <p><strong>Remediation:</strong> ${{escapeHtml(finding.remediation)}}</p>
            ${{finding.remediation_patch ? `
              <details class="variant">
                <summary><strong>Suggested patch (drop-in)</strong></summary>
                <pre>${{escapeHtml(finding.remediation_patch)}}</pre>
              </details>
            ` : ""}}
            <div class="replay-controls">
              <button type="button" class="button-secondary replay-toggle-btn" onclick="toggleReplay(${{finding._replayId}}, this)">Replay</button>
              <button type="button" class="button-secondary" onclick="downloadReplay(${{finding._replayId}})">Download replay (.html)</button>
            </div>
            <div class="replay-frame-wrap hidden" id="replay-wrap-${{finding._replayId}}">
              <iframe class="replay-frame" id="replay-frame-${{finding._replayId}}" title="Exploit replay"></iframe>
            </div>
            ${{variants}}
          </div>
        </details>
      `;
    }}

    function renderFindings(report) {{
      findingsSkeleton.classList.add("hidden");
      const findings = report?.findings || [];
      if (!findings.length) {{
        findingsContainer.innerHTML = "";
        findingsContainer.classList.add("hidden");
        findingsEmpty.classList.remove("hidden");
        findingsEmpty.textContent = "No successful findings yet. Talos is still running attacks.";
        return;
      }}

      findingsEmpty.classList.add("hidden");
      findingsContainer.classList.remove("hidden");

      findingRegistry = {{}};
      findings.forEach((f, i) => {{ findingRegistry[i] = f; f._replayId = i; }});

      const groups = {{}};
      for (const f of findings) {{
        const key = SEVERITY_META[f.severity] ? f.severity : "low";
        (groups[key] = groups[key] || []).push(f);
      }}

      const order = ["critical", "high", "medium", "low"];
      findingsContainer.innerHTML = order
        .filter((key) => groups[key] && groups[key].length)
        .map((key) => {{
          const meta = SEVERITY_META[key];
          const items = groups[key].map(renderFindingCard).join("");
          return `
            <div class="severity-group">
              <div class="severity-group-header" style="color: var(--${{key}});">
                ${{meta.label}}
                <span class="severity-group-count ${{badgeClass(key)}}">${{groups[key].length}}</span>
              </div>
              <div class="findings">${{items}}</div>
            </div>
          `;
        }}).join("");
    }}

    function deltaClass(before, after) {{
      if (after < before) return "delta-down";
      if (after > before) return "delta-up";
      return "delta-flat";
    }}

    function renderRunsTable() {{
      if (!labeledRuns.length) {{
        runsEmpty.classList.remove("hidden");
        runsTable.classList.add("hidden");
        return;
      }}
      runsEmpty.classList.add("hidden");
      runsTable.classList.remove("hidden");
      runsTbody.innerHTML = labeledRuns.map((run, i) => {{
        const prev = labeledRuns[i - 1];
        const cell = (key) => {{
          const val = run.counts[key] ?? 0;
          if (!prev) return `<span>${{val}}</span>`;
          const prevVal = prev.counts[key] ?? 0;
          const cls = deltaClass(prevVal, val);
          const arrow = val < prevVal ? "&darr;" : val > prevVal ? "&uarr;" : "";
          return `<span>${{val}}</span> <span class="${{cls}}">${{arrow}}</span>`;
        }};
        const riskCell = (() => {{
          if (!prev) return `<strong>${{run.risk}}</strong>`;
          const cls = deltaClass(prev.risk, run.risk);
          const arrow = run.risk < prev.risk ? "&darr;" : run.risk > prev.risk ? "&uarr;" : "";
          return `<strong>${{run.risk}}</strong> <span class="${{cls}}">${{arrow}}</span>`;
        }})();
        return `
          <tr>
            <td class="label-cell">${{escapeHtml(run.label)}}</td>
            <td><code>${{escapeHtml(run.target)}}</code></td>
            <td>${{riskCell}}</td>
            <td>${{cell("critical")}}</td>
            <td>${{cell("high")}}</td>
            <td>${{cell("medium")}}</td>
            <td>${{cell("low")}}</td>
            <td><strong>${{run.total}}</strong></td>
          </tr>
        `;
      }}).join("");
    }}

    function recordLabeledRun(label, target, report) {{
      if (!label) return;
      const counts = severityCounts(report);
      labeledRuns.push({{
        label,
        target,
        counts,
        risk: report?.stats?.risk_score ?? 0,
        total: (report?.findings || []).length
      }});
      renderRunsTable();
    }}

    let latestReport = null;
    let findingRegistry = {{}};

    async function exportReport() {{
      if (!latestReport) return;
      exportReportButton.disabled = true;
      exportReportButton.textContent = "Exporting...";
      try {{
        const response = await fetch("/api/reports/markdown", {{
          method: "POST",
          headers: {{ "Content-Type": "application/json" }},
          body: JSON.stringify(latestReport)
        }});
        if (!response.ok) throw new Error(`Export failed with status ${{response.status}}`);
        const blob = await response.blob();
        const disposition = response.headers.get("Content-Disposition") || "";
        const match = disposition.match(/filename="?([^"]+)"?/);
        const filename = match ? match[1] : "talos-report.md";
        const url = URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.href = url;
        link.download = filename;
        document.body.appendChild(link);
        link.click();
        link.remove();
        URL.revokeObjectURL(url);
      }} catch (error) {{
        statusSubtext.textContent = `Export failed: ${{error.message}}`;
      }} finally {{
        exportReportButton.disabled = false;
        exportReportButton.textContent = "Export report (.md)";
      }}
    }}

    async function toggleReplay(id, buttonEl) {{
      const wrap = document.getElementById(`replay-wrap-${{id}}`);
      const frame = document.getElementById(`replay-frame-${{id}}`);
      if (!wrap.classList.contains("hidden")) {{
        wrap.classList.add("hidden");
        buttonEl.textContent = "Replay";
        return;
      }}
      const finding = findingRegistry[id];
      if (!finding) return;
      buttonEl.disabled = true;
      const originalLabel = buttonEl.textContent;
      buttonEl.textContent = "Loading...";
      try {{
        const response = await fetch("/api/replay", {{
          method: "POST",
          headers: {{ "Content-Type": "application/json" }},
          body: JSON.stringify(finding)
        }});
        if (!response.ok) throw new Error(`Replay failed with status ${{response.status}}`);
        const replayHtml = await response.text();
        frame.srcdoc = replayHtml;
        wrap.classList.remove("hidden");
        buttonEl.textContent = "Hide replay";
      }} catch (error) {{
        statusSubtext.textContent = `Replay failed: ${{error.message}}`;
        buttonEl.textContent = originalLabel;
      }} finally {{
        buttonEl.disabled = false;
      }}
    }}

    async function downloadReplay(id) {{
      const finding = findingRegistry[id];
      if (!finding) return;
      try {{
        const response = await fetch("/api/replay/download", {{
          method: "POST",
          headers: {{ "Content-Type": "application/json" }},
          body: JSON.stringify(finding)
        }});
        if (!response.ok) throw new Error(`Download failed with status ${{response.status}}`);
        const blob = await response.blob();
        const disposition = response.headers.get("Content-Disposition") || "";
        const match = disposition.match(/filename="?([^"]+)"?/);
        const filename = match ? match[1] : "talos-replay.html";
        const url = URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.href = url;
        link.download = filename;
        document.body.appendChild(link);
        link.click();
        link.remove();
        URL.revokeObjectURL(url);
      }} catch (error) {{
        statusSubtext.textContent = `Replay download failed: ${{error.message}}`;
      }}
    }}

    async function runScan(event) {{
      event.preventDefault();
      runButton.disabled = true;
      resetStepper();
      findingsContainer.innerHTML = "";
      findingsContainer.classList.add("hidden");
      findingsEmpty.classList.add("hidden");
      findingsSkeleton.classList.remove("hidden");
      setStats({{ tools_found: 0, attacks_run: 0, attacks_total: 0, critical: 0, high: 0 }});
      statusText.textContent = "Starting scan...";
      statusSubtext.textContent = "Connecting to target.";

      const payload = collectScanPayload();
      const runLabel = document.getElementById("run_label").value.trim();
      let lastReport = null;

      try {{
        const response = await fetch("/api/scans", {{
          method: "POST",
          headers: {{ "Content-Type": "application/json" }},
          body: JSON.stringify(payload)
        }});

        if (!response.ok || !response.body) {{
          throw new Error(`Request failed with status ${{response.status}}`);
        }}

        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let buffer = "";

        while (true) {{
          const {{ value, done }} = await reader.read();
          if (done) break;
          buffer += decoder.decode(value, {{ stream: true }});
          const lines = buffer.split("\\n");
          buffer = lines.pop() || "";
          for (const line of lines) {{
            if (!line.trim()) continue;
            const eventData = JSON.parse(line);
            statusText.textContent = eventData.message;
            statusSubtext.textContent = eventData.type === "completed"
              ? "Scan finished. Review the final findings below."
              : "Talos is actively progressing through the live target.";
            setStepper(eventData.type);
            setStats(eventData.stats, eventData.report || lastReport);
            if (eventData.report) {{
              lastReport = eventData.report;
              latestReport = eventData.report;
              exportReportButton.disabled = false;
              renderFindings(eventData.report);
            }}
            if (eventData.type === "error") {{
              throw new Error(eventData.message);
            }}
          }}
        }}
        if (lastReport) {{
          recordLabeledRun(runLabel, payload.target, lastReport);
        }}
      }} catch (error) {{
        statusText.textContent = "Scan failed.";
        statusSubtext.textContent = error.message;
        findingsSkeleton.classList.add("hidden");
        findingsEmpty.classList.remove("hidden");
        findingsEmpty.textContent = "The scan stopped before any final results were produced.";
      }} finally {{
        await refreshLearning().catch(() => {{}});
        runButton.disabled = false;
      }}
    }}

    function renderMonitorHistory(snapshot) {{
      const history = snapshot?.history || [];
      if (!history.length) {{
        monitorHistory.innerHTML = "";
        monitorHistory.classList.add("hidden");
        monitorHistoryEmpty.classList.remove("hidden");
        return;
      }}

      monitorHistoryEmpty.classList.add("hidden");
      monitorHistory.classList.remove("hidden");
      monitorHistory.innerHTML = history.map((run, index) => {{
        const report = run.report;
        const counts = report?.stats?.severity_counts || {{ critical: 0, high: 0 }};
        const findingsCount = report?.findings?.length || 0;
        return `
          <div class="history-card">
            <h3>Run #${{snapshot.run_count - index}}</h3>
            <div class="history-meta">
              <span>status: <strong>${{escapeHtml(run.status)}}</strong></span>
              <span>started: <strong>${{new Date(run.started_at * 1000).toLocaleTimeString()}}</strong></span>
              <span>duration: <strong>${{run.duration_seconds ?? "..."}}s</strong></span>
            </div>
            <div class="history-meta">
              <span>findings: <strong>${{findingsCount}}</strong></span>
              <span>critical: <strong>${{counts.critical ?? 0}}</strong></span>
              <span>high: <strong>${{counts.high ?? 0}}</strong></span>
            </div>
            <div class="status-subtext">${{escapeHtml(run.error || run.message)}}</div>
          </div>
        `;
      }}).join("");
    }}

    function renderAlerts(alerts) {{
      if (!alerts.length) {{
        alertsList.innerHTML = "";
        alertsList.classList.add("hidden");
        alertsEmpty.classList.remove("hidden");
        return;
      }}

      alertsEmpty.classList.add("hidden");
      alertsList.classList.remove("hidden");
      alertsList.innerHTML = alerts.map((alert) => `
        <div class="alert-card">
          <div class="finding-header">
            <div>
              <h3>${{escapeHtml(alert.title)}}</h3>
              <div class="status-subtext">${{escapeHtml(alert.message)}}</div>
            </div>
            <span class="${{badgeClass(alert.severity)}}">${{escapeHtml(alert.severity)}}</span>
          </div>
          <div class="history-meta">
            <span>Kind: <strong>${{escapeHtml(alert.kind)}}</strong></span>
            <span>Time: <strong>${{new Date(alert.created_at * 1000).toLocaleString()}}</strong></span>
          </div>
        </div>
      `).join("");
    }}

    function renderLearning(summary) {{
      if (!summary || (summary.total_findings || 0) === 0) {{
        learningSummary.innerHTML = "";
        learningSummary.classList.add("hidden");
        learningEmpty.classList.remove("hidden");
        return;
      }}

      const renderList = (items) => items.map((item) => `
        <li><strong>${{escapeHtml(item.key)}}</strong> — score ${{escapeHtml(item.weighted_score)}}, success ${{escapeHtml(Math.round((item.success_rate || 0) * 100))}}%</li>
      `).join("");

      learningEmpty.classList.add("hidden");
      learningSummary.classList.remove("hidden");
      learningSummary.innerHTML = `
        <div class="learning-card">
          <h3>Overview</h3>
          <div class="history-meta">
            <span>Observed findings: <strong>${{summary.total_findings}}</strong></span>
            <span>Successful findings: <strong>${{summary.successful_findings}}</strong></span>
          </div>
        </div>
        <div class="learning-card">
          <h3>Top exploit classes</h3>
          <ul>${{renderList(summary.exploit_class_stats || [])}}</ul>
        </div>
        <div class="learning-card">
          <h3>Top templates</h3>
          <ul>${{renderList(summary.template_stats || [])}}</ul>
        </div>
      `;
    }}

    function updateMonitorUI(snapshot) {{
      if (!snapshot) return;
      activeMonitorId = snapshot.active ? snapshot.monitor_id : activeMonitorId === snapshot.monitor_id ? null : activeMonitorId;
      startMonitorButton.disabled = Boolean(snapshot.active);
      stopMonitorButton.disabled = !snapshot.active;
      monitorStatusText.textContent = snapshot.active
        ? `Monitor running (${{snapshot.status}})`
        : `Monitor ${{snapshot.status}}`;
      const nextRunText = snapshot.next_run_at
        ? `Next run at ${{new Date(snapshot.next_run_at * 1000).toLocaleTimeString()}}.`
        : "No further runs scheduled.";
      monitorStatusSubtext.textContent = `${{snapshot.config.target}} via ${{snapshot.config.adapter}}. Completed runs: ${{snapshot.run_count}}. ${{nextRunText}}`;
      renderMonitorHistory(snapshot);
      if (snapshot.latest_report) {{
        setStats({{
          tools_found: snapshot.latest_report.stats.tools_found,
          attacks_run: snapshot.latest_report.stats.attack_templates_run,
          attacks_total: snapshot.latest_report.stats.attack_templates_run,
          critical: snapshot.latest_report.stats.severity_counts.critical,
          high: snapshot.latest_report.stats.severity_counts.high,
          risk_score: snapshot.latest_report.stats.risk_score
        }}, snapshot.latest_report);
        latestReport = snapshot.latest_report;
        exportReportButton.disabled = false;
        renderFindings(snapshot.latest_report);
      }}
    }}

    async function pollMonitor() {{
      if (!activeMonitorId) return;
      try {{
        const response = await fetch(`/api/monitors/${{activeMonitorId}}`);
        if (!response.ok) throw new Error(`Monitor fetch failed with status ${{response.status}}`);
        const snapshot = await response.json();
        updateMonitorUI(snapshot);
        await refreshAlerts(activeMonitorId);
        if (!snapshot.active && monitorPollTimer) {{
          clearInterval(monitorPollTimer);
          monitorPollTimer = null;
        }}
      }} catch (error) {{
        monitorStatusText.textContent = "Monitor refresh failed.";
        monitorStatusSubtext.textContent = error.message;
      }}
    }}

    async function refreshAlerts(monitorId = null) {{
      const url = monitorId ? `/api/alerts?monitor_id=${{encodeURIComponent(monitorId)}}` : "/api/alerts";
      const response = await fetch(url);
      if (!response.ok) {{
        throw new Error(`Alerts fetch failed with status ${{response.status}}`);
      }}
      const alerts = await response.json();
      renderAlerts(alerts);
    }}

    async function refreshLearning() {{
      const response = await fetch("/api/learning/summary");
      if (!response.ok) {{
        throw new Error(`Learning fetch failed with status ${{response.status}}`);
      }}
      const summary = await response.json();
      renderLearning(summary);
    }}

    async function startMonitor() {{
      startMonitorButton.disabled = true;
      const payload = {{
        ...collectScanPayload(),
        interval_seconds: Number(document.getElementById("monitor_interval_seconds").value || 30),
        max_runs: document.getElementById("monitor_max_runs").value
          ? Number(document.getElementById("monitor_max_runs").value)
          : null
      }};

      try {{
        const response = await fetch("/api/monitors", {{
          method: "POST",
          headers: {{ "Content-Type": "application/json" }},
          body: JSON.stringify(payload)
        }});
        if (!response.ok) {{
          throw new Error(`Monitor request failed with status ${{response.status}}`);
        }}
        const snapshot = await response.json();
        activeMonitorId = snapshot.monitor_id;
        updateMonitorUI(snapshot);
        await refreshAlerts(activeMonitorId);
        await refreshLearning();
        if (monitorPollTimer) clearInterval(monitorPollTimer);
        monitorPollTimer = setInterval(pollMonitor, 2000);
        await pollMonitor();
      }} catch (error) {{
        monitorStatusText.textContent = "Failed to start monitor.";
        monitorStatusSubtext.textContent = error.message;
        startMonitorButton.disabled = false;
      }}
    }}

    async function stopMonitor() {{
      if (!activeMonitorId) return;
      stopMonitorButton.disabled = true;
      try {{
        const response = await fetch(`/api/monitors/${{activeMonitorId}}/stop`, {{ method: "POST" }});
        if (!response.ok) {{
          throw new Error(`Stop request failed with status ${{response.status}}`);
        }}
        const snapshot = await response.json();
        updateMonitorUI(snapshot);
        if (monitorPollTimer) {{
          clearInterval(monitorPollTimer);
          monitorPollTimer = null;
        }}
        activeMonitorId = null;
        startMonitorButton.disabled = false;
        await refreshAlerts();
        await refreshLearning();
      }} catch (error) {{
        monitorStatusText.textContent = "Failed to stop monitor.";
        monitorStatusSubtext.textContent = error.message;
      }}
    }}

    form.addEventListener("submit", runScan);
    exportReportButton.addEventListener("click", exportReport);
    startMonitorButton.addEventListener("click", startMonitor);
    stopMonitorButton.addEventListener("click", stopMonitor);
    refreshAlerts().catch(() => {{}});
    refreshLearning().catch(() => {{}});
  </script>
</body>
</html>"""


@app.get("/", response_class=HTMLResponse)
def dashboard_home() -> str:
    return _dashboard_html()


@app.post("/api/reports/markdown")
def export_report_markdown(report: ScanReport) -> PlainTextResponse:
    """Render a previously-streamed ScanReport (as the dashboard already has
    it client-side from a completed scan) back into the same Markdown format
    the CLI writes to disk, as a downloadable vulnerability disclosure doc.
    Stateless by design -- the client sends back the report it already has,
    so no server-side scan history/database is needed for this to work."""
    markdown = render_markdown_report(report)
    filename = f"talos-report-{report.adapter}-{int(time.time())}.md"
    return PlainTextResponse(
        content=markdown,
        media_type="text/markdown",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.post("/api/replay")
def export_replay_html(finding: ReportFinding) -> HTMLResponse:
    """Render one finding's attack conversation as a self-contained,
    animated 'case-file' HTML document (talos/talos/replay.py) -- served
    two ways from this one endpoint: the dashboard embeds the response
    directly via <iframe srcdoc> for the in-place 'Replay' toggle, and the
    'Download replay (.html)' button downloads the identical bytes as a
    standalone file. Stateless, same pattern as /api/reports/markdown."""
    replay_html = render_replay_html(finding.model_dump(mode="json"))
    return HTMLResponse(content=replay_html)


@app.post("/api/replay/download")
def download_replay_html(finding: ReportFinding) -> HTMLResponse:
    replay_html = render_replay_html(finding.model_dump(mode="json"))
    safe_tool = "".join(c if c.isalnum() else "-" for c in finding.target_tool)[:40]
    filename = f"talos-replay-{safe_tool}-{int(time.time())}.html"
    return HTMLResponse(
        content=replay_html,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/healthz")
def healthcheck() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/scans")
def run_scan(request: ScanRequest) -> StreamingResponse:
    if request.adapter not in ADAPTERS:
        raise HTTPException(status_code=422, detail=f"Unknown adapter '{request.adapter}'. Choices: {list(ADAPTERS)}")
    if request.strategy not in GENERATION_STRATEGIES:
        raise HTTPException(status_code=422, detail=f"Unknown strategy '{request.strategy}'. Choices: {list(GENERATION_STRATEGIES)}")

    def stream() -> Iterator[str]:
        try:
            for event in iter_scan_progress(
                target=request.target,
                adapter_name=request.adapter,
                attacker_email=request.attacker_email,
                seed_order_ids=request.seed_order_ids,
                poisoned_order_ids=request.poisoned_order_ids,
                repro_runs=request.repro_runs,
                generation_strategy=request.strategy,
                attack_model=request.attack_model,
            ):
                yield json.dumps(event.model_dump(mode="json")) + "\n"
        except Exception as exc:
            error_event = {
                "type": "error",
                "message": str(exc),
                "stats": {"tools_found": 0, "attacks_run": 0, "attacks_total": 0, "critical": 0, "high": 0},
            }
            yield json.dumps(error_event) + "\n"

    return StreamingResponse(stream(), media_type="application/x-ndjson")


@app.get("/api/monitors")
def list_monitors() -> list[MonitorSnapshot]:
    return monitoring_manager.list_monitors()


@app.get("/api/alerts")
def list_alerts(monitor_id: str | None = None) -> list[AlertRecord]:
    return monitoring_manager.list_alerts(monitor_id=monitor_id)


@app.get("/api/learning/summary")
def get_learning_summary() -> LearningSummary:
    return learning_store.get_summary()


@app.post("/api/monitors")
def create_monitor(request: MonitorRequest) -> MonitorSnapshot:
    if request.adapter not in ADAPTERS:
        raise HTTPException(status_code=422, detail=f"Unknown adapter '{request.adapter}'. Choices: {list(ADAPTERS)}")
    if request.strategy not in GENERATION_STRATEGIES:
        raise HTTPException(status_code=422, detail=f"Unknown strategy '{request.strategy}'. Choices: {list(GENERATION_STRATEGIES)}")
    try:
        return monitoring_manager.create_monitor(
            MonitorConfig(
                target=request.target,
                adapter=request.adapter,
                attacker_email=request.attacker_email,
                seed_order_ids=request.seed_order_ids,
                poisoned_order_ids=request.poisoned_order_ids,
                repro_runs=request.repro_runs,
                strategy=request.strategy,
                attack_model=request.attack_model,
                interval_seconds=request.interval_seconds,
                max_runs=request.max_runs,
            )
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.get("/api/monitors/{monitor_id}")
def get_monitor(monitor_id: str) -> MonitorSnapshot:
    try:
        return monitoring_manager.get_monitor(monitor_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"No such monitor: {monitor_id}") from exc


@app.post("/api/monitors/{monitor_id}/stop")
def stop_monitor(monitor_id: str) -> MonitorSnapshot:
    try:
        return monitoring_manager.stop_monitor(monitor_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"No such monitor: {monitor_id}") from exc


def _wait_and_open(url: str, ready_url: str) -> None:
    deadline = time.time() + 20
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(ready_url, timeout=1):
                webbrowser.open(url)
                return
        except Exception:
            time.sleep(0.25)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="talos-dashboard", description="Start the Talos web dashboard.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--no-open", action="store_true", help="Start the server without opening a browser tab")
    args = parser.parse_args(argv)

    browser_host = "127.0.0.1" if args.host in {"0.0.0.0", "::"} else args.host
    dashboard_url = f"http://{browser_host}:{args.port}/"
    if not args.no_open:
        opener = threading.Thread(
            target=_wait_and_open,
            args=(dashboard_url, f"http://{browser_host}:{args.port}/healthz"),
            daemon=True,
        )
        opener.start()

    uvicorn.run(app, host=args.host, port=args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
