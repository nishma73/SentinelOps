"""FastAPI Web Application & API Server for SentinelOps.

Provides REST endpoints, protected JSON-RPC 2.0 MCP interface,
and serves the single-page interactive triage dashboard.
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

# Ensure src/ directory is on sys.path for direct script execution and container runtimes
src_path = Path(__file__).resolve().parent / "src"
if str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from sentinelops.agent import get_triage_agent
from sentinelops.approval_queue import ApprovalError, get_approval_queue
from sentinelops.config import get_settings, setup_logging
from sentinelops.mcp_server import get_mcp_server
from sentinelops.scheduler import (
    get_scheduler_state,
    is_paused,
    run_job,
    set_paused,
)

# Initialize logging with secret redaction filter
settings = get_settings()
logger = setup_logging(settings)

app = FastAPI(
    title="SentinelOps",
    description="Guarded Customer Support & Incident Triage Agent with MCP and Cryptographic Approval Queue",
    version="1.0.0",
)

# Configure CORS
origins = settings.ALLOWED_ORIGINS if settings.ALLOWED_ORIGINS else ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

STATIC_DIR = Path(__file__).resolve().parent / "static"
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


# ----------------------------------------------------------------------
# Request / Response Schemas
# ----------------------------------------------------------------------


class TriageRequest(BaseModel):
    ticket_id: str = Field(default="TCK-9901")
    account_id: str = Field(default="ACC-101")
    customer_name: str = Field(default="Acme Corp")
    issue: str = Field(default="504 Gateway Timeout during checkout, requesting 20% SLA credit.")
    simulate_low_score: bool = Field(default=False)


class ApproveRequest(BaseModel):
    by: str = Field(default="human.operator@sentinelops.internal")
    seen_hash: str


class RejectRequest(BaseModel):
    by: str = Field(default="human.operator@sentinelops.internal")
    reason: str = Field(default="Rejected: Credit amount or wording not approved.")


class EditRequest(BaseModel):
    by: str = Field(default="human.operator@sentinelops.internal")
    new_payload: Dict[str, Any]


class TamperRequest(BaseModel):
    altered_body: Optional[str] = Field(
        default="[UNAUTHORIZED MODIFICATION]: We are crediting 100% of your ARR and providing lifetime free service."
    )


class PauseRequest(BaseModel):
    paused: bool


class SchedulerJobRequest(BaseModel):
    job_name: str = Field(default="triage")
    period: str = Field(default="hourly")
    simulate_failure: bool = Field(default=False)


# ----------------------------------------------------------------------
# Authentication & Authorization for MCP Endpoint
# ----------------------------------------------------------------------


def verify_mcp_auth(authorization: Optional[str] = Header(None)) -> str:
    """Verify Bearer token authentication for JSON-RPC 2.0 MCP endpoint."""
    expected_token = settings.MCP_AUTH_TOKEN
    # In development mode with blank token, allow demo access with warning
    if settings.APP_ENV == "development" and not expected_token:
        return "dev-authorized"

    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )

    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authorization scheme: expected Bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = parts[1]
    if token != expected_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return token


# ----------------------------------------------------------------------
# Endpoints
# ----------------------------------------------------------------------


@app.get("/")
def serve_index():
    """Serve single-page frontend dashboard."""
    index_file = STATIC_DIR / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    return {
        "service": "SentinelOps",
        "status": "online",
        "docs": "/docs",
        "dashboard": "/static/index.html",
    }


@app.get("/health")
def health_check(simulate_degraded: bool = False):
    """Health check endpoint.

    Returns:
    - 200 OK: {"status": "ok", ...}
    - 503 Degraded: {"status": "degraded", "error_class": "..."}
      Strict requirement: Report ONLY exception class names, never raw error messages.
    """
    try:
        if simulate_degraded:
            raise RuntimeError("Simulation")

        # Verify configuration and core queue state
        queue = get_approval_queue()
        queue_size = len(queue.list_all())
        paused_state = is_paused()

        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "status": "ok",
                "app_env": settings.APP_ENV,
                "mock_mode": settings.MOCK_MODE,
                "paused": paused_state,
                "queue_size": queue_size,
            },
        )
    except Exception as exc:
        logger.warning("Health check degraded: %s", exc.__class__.__name__)
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "status": "degraded",
                "error_class": exc.__class__.__name__,
            },
        )


@app.post("/mcp")
async def mcp_rpc_endpoint(
    request: Request,
    auth: str = Depends(verify_mcp_auth),
):
    """JSON-RPC 2.0 endpoint for Model Context Protocol (MCP) clients."""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "jsonrpc": "2.0",
                "error": {
                    "code": -32700,
                    "message": "Parse error: invalid JSON",
                },
                "id": None,
            },
        )

    mcp = get_mcp_server()
    response_data = mcp.dispatch(body)

    # In JSON-RPC 2.0, notifications (requests without 'id') produce no response
    if response_data is None:
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    return JSONResponse(status_code=status.HTTP_200_OK, content=response_data)


@app.post("/api/triage")
def run_triage(payload: TriageRequest):
    """Execute end-to-end incident triage: MCP lookups -> QA Gate -> Approval Proposal."""
    agent = get_triage_agent()
    result = agent.triage_ticket(
        ticket_id=payload.ticket_id,
        account_id=payload.account_id,
        customer_name=payload.customer_name,
        issue=payload.issue,
        simulate_low_score=payload.simulate_low_score,
    )
    return result


@app.get("/api/queue")
def list_queue():
    """Retrieve all actions in the Human-in-the-Loop approval queue."""
    queue = get_approval_queue()
    items = [item.to_dict() for item in queue.list_all()]
    return {"items": items, "count": len(items)}


@app.post("/api/queue/{action_id}/approve")
def approve_action(action_id: str, payload: ApproveRequest):
    """Cryptographically approve an action item using the seen SHA-256 payload hash."""
    queue = get_approval_queue()
    try:
        item = queue.approve(
            action_id=action_id,
            by=payload.by,
            seen_hash=payload.seen_hash,
        )
        return {"status": "approved", "item": item.to_dict()}
    except ApprovalError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )


@app.post("/api/queue/{action_id}/reject")
def reject_action(action_id: str, payload: RejectRequest):
    """Reject an action item with recorded reason."""
    queue = get_approval_queue()
    try:
        item = queue.reject(
            action_id=action_id,
            by=payload.by,
            reason=payload.reason,
        )
        return {"status": "rejected", "item": item.to_dict()}
    except ApprovalError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )


@app.post("/api/queue/{action_id}/edit")
def edit_action(action_id: str, payload: EditRequest):
    """Edit payload of a proposed action item, recalculating SHA-256 digest."""
    queue = get_approval_queue()
    try:
        item = queue.edit(
            action_id=action_id,
            by=payload.by,
            new_payload=payload.new_payload,
        )
        return {"status": "edited", "item": item.to_dict()}
    except ApprovalError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )


@app.post("/api/queue/{action_id}/tamper")
def simulate_tamper(action_id: str, payload: TamperRequest):
    """Directly mutate stored payload post-approval to demonstrate cryptographic hash lock block."""
    queue = get_approval_queue()
    item = queue.get(action_id)
    if not item:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Action '{action_id}' not found",
        )

    # Directly mutate stored payload without re-calculating or going through queue.edit()
    item.payload["body"] = payload.altered_body
    item.payload["_tampered_by_security_test"] = True

    return {
        "status": "tampered",
        "action_id": action_id,
        "note": "Payload altered in memory. Try executing now: execution will be blocked!",
        "current_payload": item.payload,
    }


@app.post("/api/queue/{action_id}/execute")
def execute_action(action_id: str):
    """Idempotently execute an approved action item with SHA-256 tamper lock."""
    queue = get_approval_queue()
    try:
        result = queue.execute(action_id)
        return {"status": "executed", "result": result}
    except ApprovalError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )


@app.get("/api/audit")
def get_audit_trail(action_id: Optional[str] = None):
    """Retrieve full or action-filtered audit log."""
    queue = get_approval_queue()
    events = [e.to_dict() for e in queue.get_audit_log(action_id)]
    return {"events": events, "count": len(events)}


@app.get("/api/pause")
def get_pause_status():
    """Get pause switch status."""
    return {"paused": is_paused()}


@app.post("/api/pause")
def set_pause_status(payload: PauseRequest):
    """Activate or deactivate pause switch."""
    new_state = set_paused(payload.paused)
    return {"paused": new_state}


@app.post("/api/scheduler/run")
def trigger_scheduled_job(payload: SchedulerJobRequest):
    """Trigger a periodic triage job through the idempotent scheduler."""
    def sample_job():
        if payload.simulate_failure:
            raise RuntimeError("Simulated transient network timeout")
        return {"tickets_scanned": 12, "auto_triaged": 4, "queued_for_approval": 2}

    result = run_job(
        job_fn=sample_job,
        job_name=payload.job_name,
        period=payload.period,
        max_attempts=3,
    )
    return result


@app.get("/api/scheduler/state")
def get_scheduler_info():
    """Retrieve current scheduler circuit breaker state and alerts."""
    state = get_scheduler_state()
    return {
        "executed_keys": list(state.executed_keys),
        "tripped_keys": list(state.tripped_keys),
        "failure_counts": state.failure_counts,
        "alerts": state.alerts,
    }
