"""Tests for JSON-RPC 2.0 MCP Server and Schema Validation."""

import json
import pytest
from sentinelops.mcp_server import (
    INVALID_PARAMS,
    INVALID_REQUEST,
    METHOD_NOT_FOUND,
    MCPServer,
    ToolRegistry,
    validate_schema,
)


def test_schema_validator_rejects_bool_for_integer_and_number():
    schema = {
        "type": "object",
        "properties": {
            "count": {"type": "integer"},
            "ratio": {"type": "number"},
            "flag": {"type": "boolean"},
        },
        "required": ["count", "ratio"],
        "additionalProperties": False,
    }

    # In Python, isinstance(True, int) is True! Ensure we strictly reject True as integer
    is_valid, errors = validate_schema(schema, {"count": True, "ratio": 1.5, "flag": True})
    assert not is_valid
    assert any("expected integer, got bool" in err for err in errors)

    # Reject bool for number
    is_valid, errors = validate_schema(schema, {"count": 10, "ratio": False, "flag": True})
    assert not is_valid
    assert any("expected number, got bool" in err for err in errors)

    # Valid types
    is_valid, errors = validate_schema(schema, {"count": 10, "ratio": 1.5, "flag": True})
    assert is_valid
    assert len(errors) == 0


def test_schema_validator_catches_missing_and_unknown_fields():
    schema = {
        "type": "object",
        "properties": {
            "name": {"type": "string"},
            "category": {"type": "string"},
        },
        "required": ["name"],
        "additionalProperties": False,
    }

    # Missing required
    is_valid, errors = validate_schema(schema, {"category": "sla"})
    assert not is_valid
    assert any("Missing required argument: 'name'" in err for err in errors)

    # Unknown field
    is_valid, errors = validate_schema(schema, {"name": "test", "extra_field": 123})
    assert not is_valid
    assert any("Unknown argument: 'extra_field'" in err for err in errors)


def test_mcp_json_rpc_invalid_request():
    server = MCPServer()

    # Non-dictionary request
    resp = server.dispatch("not a dict")
    assert resp["error"]["code"] == INVALID_REQUEST

    # Missing or bad jsonrpc version
    resp = server.dispatch({"jsonrpc": "1.0", "method": "tools/list", "id": 1})
    assert resp["error"]["code"] == INVALID_REQUEST

    # Non-string method
    resp = server.dispatch({"jsonrpc": "2.0", "method": 123, "id": 1})
    assert resp["error"]["code"] == INVALID_REQUEST


def test_mcp_json_rpc_method_not_found():
    server = MCPServer()
    resp = server.dispatch({
        "jsonrpc": "2.0",
        "method": "unsupported/method",
        "id": "req-99",
    })
    assert resp["error"]["code"] == METHOD_NOT_FOUND
    assert resp["id"] == "req-99"


def test_mcp_json_rpc_notification_without_id():
    server = MCPServer()
    # Notification (no id field) returns None in JSON-RPC 2.0
    resp = server.dispatch({
        "jsonrpc": "2.0",
        "method": "tools/list",
    })
    assert resp is None


def test_mcp_tools_list():
    server = MCPServer()
    resp = server.dispatch({
        "jsonrpc": "2.0",
        "method": "tools/list",
        "id": "list-1",
    })
    assert resp["id"] == "list-1"
    tools = resp["result"]["tools"]
    tool_names = [t["name"] for t in tools]
    assert "search_runbooks" in tool_names
    assert "lookup_customer_account" in tool_names
    assert "propose_customer_reply" in tool_names


def test_mcp_tools_call_unknown_tool_returns_invalid_params():
    server = MCPServer()
    resp = server.dispatch({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "unknown_tool_xyz",
            "arguments": {},
        },
        "id": "call-1",
    })
    assert resp["error"]["code"] == INVALID_PARAMS
    assert "Unknown tool" in resp["error"]["message"]


def test_mcp_tools_call_schema_validation_failure():
    server = MCPServer()
    # Pass boolean for string argument 'query'
    resp = server.dispatch({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "search_runbooks",
            "arguments": {
                "query": True,  # boolean rejected for string
                "category": "sla",
            },
        },
        "id": "call-2",
    })
    assert resp["id"] == "call-2"
    result = resp["result"]
    assert result["isError"] is True
    assert "expected string, got bool" in result["content"][0]["text"]


def test_mcp_tools_call_search_runbooks():
    server = MCPServer()
    resp = server.dispatch({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "search_runbooks",
            "arguments": {
                "query": "504 outage sla credit",
                "category": "sla",
            },
        },
        "id": "call-3",
    })
    assert resp["id"] == "call-3"
    result = resp["result"]
    assert result["isError"] is False
    content_text = result["content"][0]["text"]
    data = json.loads(content_text)
    assert len(data) > 0
    assert any("RB-SLA-001" in rb["id"] for rb in data)


def test_mcp_tools_call_lookup_customer_account():
    server = MCPServer()
    resp = server.dispatch({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "lookup_customer_account",
            "arguments": {
                "account_id": "ACC-101",
            },
        },
        "id": "call-4",
    })
    result = resp["result"]
    assert result["isError"] is False
    data = json.loads(result["content"][0]["text"])
    assert data["name"] == "Acme Corp"
    assert data["tier"] == "Enterprise"


def test_mcp_tools_call_propose_customer_reply():
    server = MCPServer()
    resp = server.dispatch({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "propose_customer_reply",
            "arguments": {
                "ticket_id": "TCK-100",
                "recipient": "customer@acme.corp",
                "subject": "Regarding Ticket TCK-100",
                "body": "Your issue has been resolved.",
            },
        },
        "id": "call-5",
    })
    result = resp["result"]
    assert result["isError"] is False
    data = json.loads(result["content"][0]["text"])
    assert data["status"] == "pending_approval"
    assert "action_id" in data
    assert "seen_hash" in data
