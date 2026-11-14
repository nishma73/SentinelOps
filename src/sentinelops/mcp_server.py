"""Minimal JSON-RPC 2.0 Model Context Protocol (MCP) Server with strict schema validation.

Exposes tools for runbook search, customer lookup, and human-in-the-loop reply proposal,
with full JSON-RPC 2.0 error handling and type-safe parameter validation.
"""

from __future__ import annotations

import functools
import inspect
import json
import os
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, Type, get_type_hints

from sentinelops.approval_queue import get_approval_queue

# Standard JSON-RPC 2.0 error codes
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603

DATA_DIR = Path(__file__).resolve().parent / "data"


def _type_to_json_schema(py_type: Type) -> str:
    """Map Python type to JSON Schema type string."""
    if py_type is str:
        return "string"
    if py_type is bool:
        return "boolean"
    if py_type is int:
        return "integer"
    if py_type is float:
        return "number"
    if py_type in (list, List):
        return "array"
    if py_type in (dict, Dict):
        return "object"
    return "string"


def validate_schema(
    schema: Dict[str, Any], arguments: Any
) -> Tuple[bool, List[str]]:
    """Strictly validate arguments against a JSON schema.

    Enforces:
    - Object type check
    - Strict rejection of bool for int/number
    - Missing required fields
    - Unknown/extra fields (additionalProperties: False)
    - Type conformity
    """
    errors: List[str] = []

    if not isinstance(arguments, dict):
        return False, [f"Expected arguments to be a JSON object, got {type(arguments).__name__}"]

    properties = schema.get("properties", {})
    required = schema.get("required", [])
    allow_additional = schema.get("additionalProperties", False)

    # Check required fields
    for field in required:
        if field not in arguments:
            errors.append(f"Missing required argument: '{field}'")

    # Check unknown fields
    if not allow_additional:
        for field in arguments:
            if field not in properties:
                errors.append(f"Unknown argument: '{field}' is not permitted")

    # Check types of present fields
    for field, val in arguments.items():
        if field not in properties:
            continue
        prop_def = properties[field]
        expected_type = prop_def.get("type")

        if val is None:
            if field in required:
                errors.append(f"Field '{field}' cannot be null")
            continue

        # CRITICAL: In Python, bool is a subclass of int (isinstance(True, int) is True).
        # We must explicitly reject booleans when expecting string, integer, number, array, or object.
        val_type = type(val)

        if expected_type == "integer":
            if val_type is bool or not isinstance(val, int):
                errors.append(
                    f"Field '{field}': expected integer, got {val_type.__name__}"
                )
        elif expected_type == "number":
            if val_type is bool or not isinstance(val, (int, float)):
                errors.append(
                    f"Field '{field}': expected number, got {val_type.__name__}"
                )
        elif expected_type == "string":
            if not isinstance(val, str):
                errors.append(
                    f"Field '{field}': expected string, got {val_type.__name__}"
                )
        elif expected_type == "boolean":
            if not isinstance(val, bool):
                errors.append(
                    f"Field '{field}': expected boolean, got {val_type.__name__}"
                )
        elif expected_type == "array":
            if not isinstance(val, list):
                errors.append(
                    f"Field '{field}': expected array, got {val_type.__name__}"
                )
        elif expected_type == "object":
            if not isinstance(val, dict):
                errors.append(
                    f"Field '{field}': expected object, got {val_type.__name__}"
                )

    return len(errors) == 0, errors


class ToolRegistry:
    """Registry for MCP tools with automatic schema generation and strict validation."""

    def __init__(self):
        self._tools: Dict[str, Dict[str, Any]] = {}

    def tool(
        self,
        name: Optional[str] = None,
        description: Optional[str] = None,
    ):
        """Decorator to register a Python function as an MCP tool."""

        def decorator(func: Callable):
            tool_name = name or func.__name__
            tool_desc = description or (func.__doc__ or "").strip().split("\n")[0]

            sig = inspect.signature(func)
            type_hints = get_type_hints(func)

            properties: Dict[str, Any] = {}
            required: List[str] = []

            for param_name, param in sig.parameters.items():
                if param_name in ("self", "cls"):
                    continue
                param_type = type_hints.get(param_name, str)
                schema_type = _type_to_json_schema(param_type)
                properties[param_name] = {
                    "type": schema_type,
                    "description": f"Parameter {param_name}",
                }
                if param.default is inspect.Parameter.empty:
                    required.append(param_name)

            input_schema = {
                "type": "object",
                "properties": properties,
                "required": required,
                "additionalProperties": False,
            }

            self._tools[tool_name] = {
                "name": tool_name,
                "description": tool_desc,
                "inputSchema": input_schema,
                "func": func,
            }

            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                return func(*args, **kwargs)

            return wrapper

        return decorator

    def list_tools(self) -> List[Dict[str, Any]]:
        """Return MCP tools list specification."""
        return [
            {
                "name": t["name"],
                "description": t["description"],
                "inputSchema": t["inputSchema"],
            }
            for t in self._tools.values()
        ]

    def has_tool(self, name: str) -> bool:
        return name in self._tools

    def get_tool(self, name: str) -> Optional[Dict[str, Any]]:
        return self._tools.get(name)

    def call_tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Call a registered tool with schema validation.

        Returns MCP tool result format with 'isError: true' on validation or execution failures.
        """
        tool_entry = self.get_tool(name)
        if not tool_entry:
            raise KeyError(f"Unknown tool: '{name}'")

        # Validate arguments against tool schema
        schema = tool_entry["inputSchema"]
        is_valid, validation_errors = validate_schema(schema, arguments)
        if not is_valid:
            error_msg = "Schema validation failed:\n" + "\n".join(
                f"- {err}" for err in validation_errors
            )
            return {
                "content": [{"type": "text", "text": error_msg}],
                "isError": True,
            }

        func = tool_entry["func"]
        try:
            result = func(**arguments)
            # Serialize result cleanly
            if isinstance(result, (dict, list)):
                result_text = json.dumps(result, indent=2)
            else:
                result_text = str(result)
            return {
                "content": [{"type": "text", "text": result_text}],
                "isError": False,
            }
        except Exception as exc:
            return {
                "content": [
                    {"type": "text", "text": f"Tool execution failed: {type(exc).__name__}: {str(exc)}"}
                ],
                "isError": True,
            }


registry = ToolRegistry()


# ----------------------------------------------------------------------
# 3 Standard SentinelOps MCP Tools
# ----------------------------------------------------------------------


@registry.tool(
    name="search_runbooks",
    description="Search company runbooks and operating procedures by query and category.",
)
def search_runbooks(query: str, category: str) -> List[Dict[str, Any]]:
    """Search runbooks for matching policies and action steps."""
    runbooks_path = DATA_DIR / "runbooks.json"
    if not runbooks_path.exists():
        return []

    with open(runbooks_path, "r", encoding="utf-8") as f:
        runbooks: List[Dict[str, Any]] = json.load(f)

    query_norm = query.strip().lower()
    cat_norm = category.strip().lower()

    matches = []
    for rb in runbooks:
        # Category filter
        rb_cat = rb.get("category", "").lower()
        if cat_norm != "all" and cat_norm != rb_cat:
            continue

        # Text matching
        text_corpus = (
            f"{rb.get('title', '')} {rb.get('summary', '')} {rb.get('policy', '')} "
            f"{' '.join(rb.get('tags', []))}"
        ).lower()

        if any(token in text_corpus for token in query_norm.split()) or not query_norm:
            matches.append(rb)

    return matches


@registry.tool(
    name="lookup_customer_account",
    description="Lookup customer profile, tier, SLA terms, and recent incidents by account_id.",
)
def lookup_customer_account(account_id: str) -> Dict[str, Any]:
    """Retrieve customer metadata and entitlement details."""
    customers_path = DATA_DIR / "customers.json"
    if not customers_path.exists():
        return {"error": "Customer database not found"}

    with open(customers_path, "r", encoding="utf-8") as f:
        customers: List[Dict[str, Any]] = json.load(f)

    aid = account_id.strip().upper()
    for cust in customers:
        if cust.get("account_id", "").upper() == aid:
            return cust

    return {"error": f"Customer account '{account_id}' not found"}


@registry.tool(
    name="propose_customer_reply",
    description="Propose a customer email reply for human-in-the-loop approval before sending.",
)
def propose_customer_reply(
    ticket_id: str, recipient: str, subject: str, body: str
) -> Dict[str, Any]:
    """Place a drafted reply in the approval queue instead of sending directly."""
    queue = get_approval_queue()
    payload = {
        "ticket_id": ticket_id,
        "recipient": recipient,
        "subject": subject,
        "body": body,
    }
    action_item = queue.propose(
        action_type="customer_reply",
        payload=payload,
        ttl_seconds=3600,
        proposed_by="sentinelops_mcp_agent",
    )
    return {
        "status": "pending_approval",
        "action_id": action_item.action_id,
        "seen_hash": action_item.seen_hash,
        "expires_at_iso": action_item.expires_at_iso,
        "message": (
            "Customer reply draft successfully queued for cryptographic human approval. "
            "It will NOT be sent until reviewed and executed by an authorized human operator."
        ),
    }


# ----------------------------------------------------------------------
# JSON-RPC 2.0 Dispatcher
# ----------------------------------------------------------------------


class MCPServer:
    """Minimal JSON-RPC 2.0 MCP Server handler."""

    def __init__(self, tool_registry: ToolRegistry = registry):
        self.registry = tool_registry

    def dispatch(self, request_data: Any) -> Optional[Dict[str, Any]]:
        """Process a JSON-RPC 2.0 request and return response dict, or None for notifications."""
        # Check invalid request structure
        if not isinstance(request_data, dict):
            return {
                "jsonrpc": "2.0",
                "error": {
                    "code": INVALID_REQUEST,
                    "message": "Invalid Request: expected JSON object",
                },
                "id": None,
            }

        req_id = request_data.get("id")
        is_notification = "id" not in request_data

        # Check jsonrpc protocol version
        if request_data.get("jsonrpc") != "2.0":
            if is_notification:
                return None
            return {
                "jsonrpc": "2.0",
                "error": {
                    "code": INVALID_REQUEST,
                    "message": "Invalid Request: 'jsonrpc' must be exactly '2.0'",
                },
                "id": req_id,
            }

        method = request_data.get("method")
        if not isinstance(method, str):
            if is_notification:
                return None
            return {
                "jsonrpc": "2.0",
                "error": {
                    "code": INVALID_REQUEST,
                    "message": "Invalid Request: 'method' must be a string",
                },
                "id": req_id,
            }

        params = request_data.get("params")

        # Route methods
        if method == "tools/list":
            result = {"tools": self.registry.list_tools()}
            if is_notification:
                return None
            return {"jsonrpc": "2.0", "result": result, "id": req_id}

        elif method == "tools/call":
            if not isinstance(params, dict):
                if is_notification:
                    return None
                return {
                    "jsonrpc": "2.0",
                    "error": {
                        "code": INVALID_PARAMS,
                        "message": "Invalid params: 'params' must be an object for 'tools/call'",
                    },
                    "id": req_id,
                }

            tool_name = params.get("name")
            if not isinstance(tool_name, str):
                if is_notification:
                    return None
                return {
                    "jsonrpc": "2.0",
                    "error": {
                        "code": INVALID_PARAMS,
                        "message": "Invalid params: missing or non-string tool 'name'",
                    },
                    "id": req_id,
                }

            if not self.registry.has_tool(tool_name):
                if is_notification:
                    return None
                return {
                    "jsonrpc": "2.0",
                    "error": {
                        "code": INVALID_PARAMS,
                        "message": f"Unknown tool: '{tool_name}'",
                    },
                    "id": req_id,
                }

            arguments = params.get("arguments", {})
            call_result = self.registry.call_tool(tool_name, arguments)
            if is_notification:
                return None
            return {"jsonrpc": "2.0", "result": call_result, "id": req_id}

        elif method == "ping":
            if is_notification:
                return None
            return {"jsonrpc": "2.0", "result": "pong", "id": req_id}

        else:
            if is_notification:
                return None
            return {
                "jsonrpc": "2.0",
                "error": {
                    "code": METHOD_NOT_FOUND,
                    "message": f"Method not found: '{method}'",
                },
                "id": req_id,
            }


_global_mcp_server: Optional[MCPServer] = None


def get_mcp_server() -> MCPServer:
    """Retrieve singleton MCPServer instance."""
    global _global_mcp_server
    if _global_mcp_server is None:
        _global_mcp_server = MCPServer(registry)
    return _global_mcp_server
