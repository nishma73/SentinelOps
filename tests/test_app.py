"""Integration tests for SentinelOps FastAPI application endpoints."""

import pytest
from fastapi.testclient import TestClient
from app import app
from sentinelops.config import get_settings

client = TestClient(app)


def test_health_check_healthy():
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert "mock_mode" in data
    assert "app_env" in data


def test_health_check_degraded_exposes_exception_class_name_only():
    resp = client.get("/health?simulate_degraded=true")
    assert resp.status_code == 503
    data = resp.json()
    assert data["status"] == "degraded"
    assert data["error_class"] == "RuntimeError"
    # STRICT REQUIREMENT: Ensure no raw exception message or secrets are leaked
    assert "Simulation" not in resp.text
    assert "detail" not in data or not data["detail"]


def test_mcp_endpoint_requires_auth_when_token_configured(monkeypatch):
    monkeypatch.setattr(get_settings(), "MCP_AUTH_TOKEN", "test_mcp_token_xyz")

    # Missing auth
    resp = client.post("/mcp", json={"jsonrpc": "2.0", "method": "tools/list", "id": 1})
    assert resp.status_code == 401

    # Invalid token
    resp = client.post(
        "/mcp",
        headers={"Authorization": "Bearer wrong_token"},
        json={"jsonrpc": "2.0", "method": "tools/list", "id": 1},
    )
    assert resp.status_code == 401

    # Valid token
    resp = client.post(
        "/mcp",
        headers={"Authorization": "Bearer test_mcp_token_xyz"},
        json={"jsonrpc": "2.0", "method": "tools/list", "id": 1},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == 1
    assert "tools" in data["result"]


def test_mcp_notification_returns_204_no_content(monkeypatch):
    monkeypatch.setattr(get_settings(), "MCP_AUTH_TOKEN", "")
    # Notification has no 'id'
    resp = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "method": "tools/list"},
    )
    assert resp.status_code == 204


def test_api_triage_end_to_end_pipeline():
    payload = {
        "ticket_id": "TCK-1001",
        "account_id": "ACC-101",
        "customer_name": "Acme Corp",
        "issue": "504 Gateway Timeout during checkout, requesting SLA credit",
        "simulate_low_score": False,
    }

    resp = client.post("/api/triage", json=payload)
    assert resp.status_code == 200
    data = resp.json()

    assert data["ticket_id"] == "TCK-1001"
    assert data["status"] == "queued_for_approval"
    assert len(data["tool_calls"]) >= 2
    assert data["reviewer_gate"]["passed"] is True
    assert data["approval_item"]["status"] == "pending_approval"
    assert "action_id" in data["approval_item"]


def test_api_triage_with_low_score_triggers_rewrite():
    payload = {
        "ticket_id": "TCK-1002",
        "account_id": "ACC-101",
        "customer_name": "Acme Corp",
        "issue": "504 Gateway Timeout during checkout, requesting SLA credit",
        "simulate_low_score": True,  # Triggers low score attempt 1 -> rewrite
    }

    resp = client.post("/api/triage", json=payload)
    assert resp.status_code == 200
    data = resp.json()

    gate = data["reviewer_gate"]
    assert gate["passed"] is True
    # Verify exactly 2 attempts were executed
    assert len(gate["attempts"]) == 2
    assert gate["attempts"][0]["passed"] is False
    assert gate["attempts"][1]["passed"] is True


def test_queue_approval_tamper_and_execution_flow():
    # 1. Triage to create queue item
    triage_resp = client.post(
        "/api/triage",
        json={
            "ticket_id": "TCK-3301",
            "account_id": "ACC-202",
            "customer_name": "Globex Dynamics",
            "issue": "SAML assertion failure",
            "simulate_low_score": False,
        },
    )
    triage_data = triage_resp.json()
    action_id = triage_data["approval_item"]["action_id"]
    seen_hash = triage_data["approval_item"]["seen_hash"]

    # 2. Approve action
    app_resp = client.post(
        f"/api/queue/{action_id}/approve",
        json={"by": "lead_reviewer", "seen_hash": seen_hash},
    )
    assert app_resp.status_code == 200
    assert app_resp.json()["status"] == "approved"

    # 3. Simulate tamper post-approval
    tamper_resp = client.post(
        f"/api/queue/{action_id}/tamper",
        json={"altered_body": "MALICIOUS ALTERATION"},
    )
    assert tamper_resp.status_code == 200

    # 4. Execute must be blocked due to hash mismatch
    exec_resp = client.post(f"/api/queue/{action_id}/execute")
    assert exec_resp.status_code == 400
    assert "Execution blocked: payload has been tampered with" in exec_resp.json()["detail"]


def test_audit_endpoint():
    resp = client.get("/api/audit")
    assert resp.status_code == 200
    data = resp.json()
    assert "events" in data
    assert isinstance(data["events"], list)
