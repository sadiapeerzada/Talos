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


class ScanRequest(BaseModel):
    target: str
    adapter: str
    attacker_email: str = DEFAULT_ATTACKER_EMAIL
    seed_order_ids: list[str] = Field(default_factory=lambda: list(DEFAULT_SEED_ORDER_IDS))
    poisoned_order_ids: list[str] = Field(default_factory=lambda: list(DEFAULT_POISONED_ORDER_IDS))
    repro_runs: int = 3
    strategy: str = DEFAULT_GENERATION_STRATEGY
    attack_model: str = "claude-sonnet-4-5"


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

      const payload = {{
        target: document.getElementById("target").value.trim(),
        adapter: document.getElementById("adapter").value,
        attacker_email: document.getElementById("attacker_email").value.trim(),
        seed_order_ids: parseList(document.getElementById("seed_order_ids").value),
        poisoned_order_ids: parseList(document.getElementById("poisoned_order_ids").value),
        strategy: document.getElementById("strategy").value,
        attack_model: document.getElementById("attack_model").value.trim()
      }};

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
        runButton.disabled = false;
      }}
    }}

    form.addEventListener("submit", runScan);
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
