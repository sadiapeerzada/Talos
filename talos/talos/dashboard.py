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
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel, Field

from talos.learning import LearningStore, LearningSummary
from talos.monitoring import AlertRecord, MonitorConfig, MonitorSnapshot, MonitoringManager
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
  <style>
    :root {{
      color-scheme: light;
      --bg: #f6f7f9;
      --panel: #ffffff;
      --border: #d9dde3;
      --text: #111827;
      --muted: #6b7280;
      --critical: #b91c1c;
      --critical-bg: #fee2e2;
      --high: #c2410c;
      --high-bg: #ffedd5;
      --medium: #92400e;
      --medium-bg: #fef3c7;
      --low: #166534;
      --low-bg: #dcfce7;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: var(--bg);
      color: var(--text);
    }}
    .page {{
      max-width: 1080px;
      margin: 0 auto;
      padding: 32px 20px 56px;
    }}
    h1 {{ margin: 0 0 8px; font-size: 2rem; }}
    .subtitle {{ margin: 0 0 28px; color: var(--muted); }}
    .panel {{
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 20px;
      margin-bottom: 18px;
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
      gap: 8px;
    }}
    label {{
      font-size: 0.92rem;
      color: var(--muted);
    }}
    input, select, button, textarea {{
      width: 100%;
      padding: 12px 14px;
      border: 1px solid var(--border);
      border-radius: 10px;
      font: inherit;
      background: #fff;
      color: inherit;
    }}
    textarea {{ min-height: 76px; resize: vertical; }}
    button {{
      width: auto;
      min-width: 140px;
      background: #111827;
      color: white;
      cursor: pointer;
      border-color: #111827;
    }}
    button:disabled {{
      opacity: 0.55;
      cursor: wait;
    }}
    details {{ margin-top: 14px; }}
    details summary {{
      cursor: pointer;
      color: var(--muted);
      user-select: none;
    }}
    .advanced {{
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 12px;
      margin-top: 14px;
    }}
    .status-row {{
      display: flex;
      justify-content: space-between;
      gap: 12px;
      align-items: center;
      flex-wrap: wrap;
      margin-bottom: 16px;
    }}
    .status-text {{
      font-weight: 600;
    }}
    .status-subtext {{
      color: var(--muted);
      font-size: 0.92rem;
      margin-top: 4px;
    }}
    .stats {{
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 12px;
    }}
    .stat {{
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 16px;
    }}
    .stat-label {{
      color: var(--muted);
      font-size: 0.88rem;
      margin-bottom: 8px;
    }}
    .stat-value {{
      font-size: 1.8rem;
      font-weight: 700;
      letter-spacing: -0.03em;
    }}
    .findings-empty {{
      color: var(--muted);
      margin: 0;
    }}
    .findings {{
      display: flex;
      flex-direction: column;
      gap: 12px;
    }}
    .monitor-actions {{
      display: flex;
      gap: 12px;
      flex-wrap: wrap;
      margin-top: 14px;
    }}
    .monitor-actions button {{
      width: auto;
    }}
    .button-secondary {{
      background: #ffffff;
      color: var(--text);
      border-color: var(--border);
    }}
    .history-list {{
      display: flex;
      flex-direction: column;
      gap: 12px;
      margin-top: 14px;
    }}
    .history-card {{
      border: 1px solid var(--border);
      border-radius: 12px;
      background: #fafafa;
      padding: 14px;
    }}
    .history-card h3 {{
      margin: 0 0 6px;
      font-size: 1rem;
    }}
    .history-meta {{
      color: var(--muted);
      font-size: 0.9rem;
      display: flex;
      gap: 12px;
      flex-wrap: wrap;
      margin-bottom: 10px;
    }}
    .monitor-empty {{
      color: var(--muted);
      margin: 0;
    }}
    .alerts-list {{
      display: flex;
      flex-direction: column;
      gap: 12px;
      margin-top: 14px;
    }}
    .alert-card {{
      border: 1px solid var(--border);
      border-radius: 12px;
      background: #fafafa;
      padding: 14px;
    }}
    .alert-card h3 {{
      margin: 0 0 6px;
      font-size: 1rem;
    }}
    .learning-grid {{
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 12px;
      margin-top: 14px;
    }}
    .learning-card {{
      border: 1px solid var(--border);
      border-radius: 12px;
      background: #fafafa;
      padding: 14px;
    }}
    .learning-card h3 {{
      margin: 0 0 10px;
      font-size: 1rem;
    }}
    .learning-card ul {{
      margin: 0;
      padding-left: 18px;
      color: var(--muted);
    }}
    .finding {{
      border: 1px solid var(--border);
      border-radius: 14px;
      background: var(--panel);
      overflow: hidden;
    }}
    .finding summary {{
      list-style: none;
      cursor: pointer;
      padding: 16px 18px;
    }}
    .finding summary::-webkit-details-marker {{ display: none; }}
    .finding-header {{
      display: flex;
      justify-content: space-between;
      gap: 12px;
      align-items: flex-start;
    }}
    .finding-title {{
      font-weight: 700;
      margin: 0 0 6px;
    }}
    .finding-summary {{
      margin: 0;
      color: var(--muted);
    }}
    .badge {{
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-width: 76px;
      padding: 6px 10px;
      border-radius: 999px;
      font-size: 0.78rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.04em;
    }}
    .badge-critical {{ color: var(--critical); background: var(--critical-bg); }}
    .badge-high {{ color: var(--high); background: var(--high-bg); }}
    .badge-medium {{ color: var(--medium); background: var(--medium-bg); }}
    .badge-low {{ color: var(--low); background: var(--low-bg); }}
    .finding-body {{
      padding: 0 18px 18px;
      border-top: 1px solid var(--border);
    }}
    .meta {{
      display: flex;
      gap: 16px;
      flex-wrap: wrap;
      color: var(--muted);
      font-size: 0.9rem;
      margin: 14px 0;
    }}
    .variant {{
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 14px;
      margin-top: 12px;
      background: #fafafa;
    }}
    .variant h4 {{
      margin: 0 0 10px;
      font-size: 0.98rem;
    }}
    ol {{
      margin: 8px 0 0 20px;
      padding: 0;
    }}
    pre {{
      margin: 8px 0 0;
      padding: 12px;
      border-radius: 10px;
      background: #111827;
      color: #f9fafb;
      overflow: auto;
      font-size: 0.85rem;
    }}
    .hidden {{ display: none; }}
    @media (max-width: 820px) {{
      form, .advanced, .stats {{
        grid-template-columns: 1fr;
      }}
      button {{ width: 100%; }}
    }}
  </style>
</head>
<body>
  <div class="page">
    <h1>Talos Dashboard</h1>
    <p class="subtitle">Run the existing Talos scan engine locally and watch findings land in real time.</p>

    <section class="panel">
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

      <details>
        <summary>Advanced options</summary>
        <div class="advanced">
          <div class="field">
            <label for="attacker_email">Attacker email</label>
            <input id="attacker_email" name="attacker_email" type="email" value="{defaults["attacker_email"]}">
          </div>
          <div class="field">
            <label for="seed_order_ids">Seed order IDs</label>
            <input id="seed_order_ids" name="seed_order_ids" type="text" value="{defaults["seed_order_ids"]}">
          </div>
          <div class="field">
            <label for="poisoned_order_ids">Poisoned order IDs</label>
            <input id="poisoned_order_ids" name="poisoned_order_ids" type="text" value="{defaults["poisoned_order_ids"]}">
          </div>
          <div class="field">
            <label for="strategy">Attack strategy</label>
            <select id="strategy" name="strategy">{strategy_options}</select>
          </div>
          <div class="field">
            <label for="attack_model">Adaptive model</label>
            <input id="attack_model" name="attack_model" type="text" value="{defaults["attack_model"]}">
          </div>
        </div>
      </details>
    </section>

    <section class="panel">
      <div class="status-row">
        <div>
          <div id="status-text" class="status-text">Ready to scan.</div>
          <div id="status-subtext" class="status-subtext">Progress updates will appear here as Talos discovers tools and runs attacks.</div>
        </div>
      </div>
      <div class="stats">
        <div class="stat">
          <div class="stat-label">Tools found</div>
          <div id="tools-found" class="stat-value">0</div>
        </div>
        <div class="stat">
          <div class="stat-label">Attacks run</div>
          <div id="attacks-run" class="stat-value">0 / 0</div>
        </div>
        <div class="stat">
          <div class="stat-label">Critical findings</div>
          <div id="critical-count" class="stat-value">0</div>
        </div>
        <div class="stat">
          <div class="stat-label">High findings</div>
          <div id="high-count" class="stat-value">0</div>
        </div>
      </div>
    </section>

    <section class="panel">
      <h2 style="margin: 0 0 14px;">Findings</h2>
      <p id="findings-empty" class="findings-empty">No findings yet. Run a scan to populate this list.</p>
      <div id="findings" class="findings hidden"></div>
    </section>

    <section class="panel">
      <h2 style="margin: 0 0 14px;">Continuous monitoring</h2>
      <p class="subtitle" style="margin: 0 0 16px;">Re-run full scans on a timer and keep a live history of results.</p>
      <div class="advanced" style="margin-top: 0;">
        <div class="field">
          <label for="monitor_interval_seconds">Interval (seconds)</label>
          <input id="monitor_interval_seconds" name="monitor_interval_seconds" type="number" min="1" step="1" value="30">
        </div>
        <div class="field">
          <label for="monitor_max_runs">Max runs (optional)</label>
          <input id="monitor_max_runs" name="monitor_max_runs" type="number" min="1" step="1" placeholder="Leave blank for continuous">
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
    const statusText = document.getElementById("status-text");
    const statusSubtext = document.getElementById("status-subtext");
    const toolsFound = document.getElementById("tools-found");
    const attacksRun = document.getElementById("attacks-run");
    const criticalCount = document.getElementById("critical-count");
    const highCount = document.getElementById("high-count");
    const findingsContainer = document.getElementById("findings");
    const findingsEmpty = document.getElementById("findings-empty");
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

    function setStats(stats) {{
      if (!stats) return;
      toolsFound.textContent = String(stats.tools_found ?? 0);
      attacksRun.textContent = `${{stats.attacks_run ?? 0}} / ${{stats.attacks_total ?? 0}}`;
      criticalCount.textContent = String(stats.critical ?? 0);
      highCount.textContent = String(stats.high ?? 0);
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

    function renderFindings(report) {{
      const findings = (report?.findings || []).slice().sort((left, right) => {{
        const order = {{ critical: 4, high: 3, medium: 2, low: 1, none: 0 }};
        return (order[right.severity] || 0) - (order[left.severity] || 0);
      }});
      if (!findings.length) {{
        findingsContainer.innerHTML = "";
        findingsContainer.classList.add("hidden");
        findingsEmpty.classList.remove("hidden");
        findingsEmpty.textContent = "No successful findings yet. Talos is still running attacks.";
        return;
      }}

      findingsEmpty.classList.add("hidden");
      findingsContainer.classList.remove("hidden");
      findingsContainer.innerHTML = findings.map((finding) => {{
        const variants = finding.variants.map((variant) => {{
          const steps = variant.messages.map((message) => `<li><code>${{escapeHtml(message)}}</code></li>`).join("");
          const evidence = escapeHtml(JSON.stringify(variant.evidence, null, 2));
          return `
            <div class="variant">
              <h4>${{escapeHtml(variant.template_id)}} - ${{escapeHtml(variant.name)}} (${{escapeHtml(variant.outcome)}})</h4>
              <div><strong>Reproduction steps</strong></div>
              <ol>${{steps}}</ol>
              <div style="margin-top: 12px;"><strong>Evidence</strong></div>
              <pre>${{evidence}}</pre>
            </div>
          `;
        }}).join("");

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
                <span>Target tool: <strong>${{escapeHtml(finding.target_tool)}}</strong></span>
                <span>Exploit class: <strong>${{escapeHtml(finding.exploit_label)}}</strong></span>
                <span>Reproducibility: <strong>${{Math.round((finding.reproducibility || 0) * 100)}}%</strong></span>
              </div>
              <p><strong>Remediation:</strong> ${{escapeHtml(finding.remediation)}}</p>
              ${{variants}}
            </div>
          </details>
        `;
      }}).join("");
    }}

    async function runScan(event) {{
      event.preventDefault();
      runButton.disabled = true;
      findingsContainer.innerHTML = "";
      findingsContainer.classList.add("hidden");
      findingsEmpty.classList.remove("hidden");
      findingsEmpty.textContent = "Starting scan...";
      setStats({{ tools_found: 0, attacks_run: 0, attacks_total: 0, critical: 0, high: 0 }});
      statusText.textContent = "Starting scan...";
      statusSubtext.textContent = "Connecting to target.";

      const payload = collectScanPayload();

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
            setStats(eventData.stats);
            if (eventData.report) {{
              renderFindings(eventData.report);
            }}
            if (eventData.type === "error") {{
              throw new Error(eventData.message);
            }}
          }}
        }}
      }} catch (error) {{
        statusText.textContent = "Scan failed.";
        statusSubtext.textContent = error.message;
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
              <span>Status: <strong>${{escapeHtml(run.status)}}</strong></span>
              <span>Started: <strong>${{new Date(run.started_at * 1000).toLocaleTimeString()}}</strong></span>
              <span>Duration: <strong>${{run.duration_seconds ?? "..."}}s</strong></span>
            </div>
            <div class="history-meta">
              <span>Findings: <strong>${{findingsCount}}</strong></span>
              <span>Critical: <strong>${{counts.critical ?? 0}}</strong></span>
              <span>High: <strong>${{counts.high ?? 0}}</strong></span>
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
          high: snapshot.latest_report.stats.severity_counts.high
        }});
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
