from __future__ import annotations

import json
import time

from fastapi.testclient import TestClient

from talos.dashboard import app


client = TestClient(app)


def test_dashboard_root_serves_html():
    response = client.get("/")

    assert response.status_code == 200
    assert "Talos Dashboard" in response.text
    assert "Run scan" in response.text
    assert "Continuous monitoring" in response.text
    assert 'id="findings"' in response.text


def test_dashboard_scan_streams_progress_and_final_report(native_server_url):
    payload = {
        "target": native_server_url,
        "adapter": "native",
        "attacker_email": "collector@exfil-sink.example",
        "seed_order_ids": ["1001", "1003"],
        "poisoned_order_ids": ["1002"],
    }

    with client.stream("POST", "/api/scans", json=payload) as response:
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("application/x-ndjson")
        events = [json.loads(line) for line in response.iter_lines() if line]

    assert events[0]["type"] == "connected"
    assert any(event["type"] == "tools_discovered" for event in events)
    assert any(event["type"] == "attacks_generated" for event in events)
    assert any(event["type"] == "attack_scored" and event["stats"]["attacks_run"] > 0 for event in events)

    final_event = events[-1]
    assert final_event["type"] == "completed"
    assert final_event["stats"]["attacks_run"] == final_event["stats"]["attacks_total"]

    report = final_event["report"]
    assert report["target"] == native_server_url
    assert report["adapter"] == "native"
    assert report["stats"]["tools_found"] > 0
    assert report["stats"]["attack_templates_run"] == final_event["stats"]["attacks_total"]
    assert report["findings"]
    first_finding = report["findings"][0]
    assert first_finding["title"]
    assert first_finding["summary"]
    assert first_finding["variants"][0]["messages"]
    assert first_finding["variants"][0]["evidence"]


def test_monitor_runs_recurring_scans_and_exposes_history(native_server_url):
    payload = {
        "target": native_server_url,
        "adapter": "native",
        "attacker_email": "collector@exfil-sink.example",
        "seed_order_ids": ["1001", "1003"],
        "poisoned_order_ids": ["1002"],
        "repro_runs": 1,
        "interval_seconds": 1,
        "max_runs": 2,
        "strategy": "template",
    }

    create_response = client.post("/api/monitors", json=payload)
    assert create_response.status_code == 200
    monitor = create_response.json()
    monitor_id = monitor["monitor_id"]

    deadline = time.time() + 15
    snapshot = monitor
    while time.time() < deadline:
        snapshot_response = client.get(f"/api/monitors/{monitor_id}")
        assert snapshot_response.status_code == 200
        snapshot = snapshot_response.json()
        if snapshot["active"] is False and snapshot["run_count"] >= 2:
            break
        time.sleep(0.2)

    assert snapshot["run_count"] == 2
    assert snapshot["status"] == "completed"
    assert snapshot["latest_report"] is not None
    assert len(snapshot["history"]) == 2
    assert snapshot["history"][0]["status"] == "succeeded"

    list_response = client.get("/api/monitors")
    assert list_response.status_code == 200
    assert any(item["monitor_id"] == monitor_id for item in list_response.json())
