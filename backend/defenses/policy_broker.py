"""
Policy Broker — tool gateway with dual-graph authorization + argument-level provenance.

Implements a lightweight version of:
- AuthGraph-style dual-graph auth (arXiv 2605.26497)
- PACT-style argument-level trust contracts (arXiv 2605.11039)

Decision: ALLOW | DENY | REDACT + reason string

The broker compares:
1. Authorization graph: what the user's CLEAN intent authorized
2. Provenance graph: what the execution trace is actually doing

Blocks when tool calls diverge from authorized intent, especially when
sensitive arguments trace to untrusted document content (not user input).
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

# ── Tool allow-list and sensitivity ──────────────────────────────────────────

_TOOL_ALLOWLIST = {"read_document", "lookup_employee"}

_SENSITIVE_TOOLS = {"lookup_employee"}

# Arguments that carry authority (if untrusted-sourced → block)
_AUTHORITY_ARGS = {
    "lookup_employee": ["employee_id"],
    "read_document": [],  # filename is low-sensitivity
}

# Trusted vs untrusted sources
_UNTRUSTED_SOURCES = {"injected_instruction", "arabic_injection", "document_content"}
_TRUSTED_SOURCES = {"user", "planner", None}


def _taint_analysis(
    tool_name: str,
    arguments: Dict[str, Any],
    messages: List[Dict[str, str]],
    tool_source: str,
    user_input: str,
) -> Dict[str, Any]:
    """
    Taint analysis: label each argument by its origin.
    Returns {arg_name: {"taint": "user"|"document"|"injected", "value": ...}}
    """
    taints = {}
    user_lower = user_input.lower() if user_input else ""

    for arg_name, arg_value in arguments.items():
        arg_str = str(arg_value).lower()
        taint = "unknown"

        # If the tool call itself is sourced from an injection
        if tool_source in _UNTRUSTED_SOURCES:
            taint = "injected"
        elif arg_str in user_lower:
            taint = "user"
        else:
            # Check if value appears in any document content in messages
            for msg in messages:
                if msg.get("role") == "tool" and arg_str in msg.get("content", "").lower():
                    taint = "document"
                    break
            if taint == "unknown":
                # Heuristic: if source is planner, assume user-derived unless proven otherwise
                taint = "user"

        taints[arg_name] = {"taint": taint, "value": arg_value}

    return taints


def _authorization_check(
    tool_name: str,
    arguments: Dict[str, Any],
    authorization_graph: Dict[str, Any],
    user_input: str,
) -> Dict[str, Any]:
    """
    AuthGraph-style check: does the tool call match the clean authorization graph?
    """
    authorized_tools = authorization_graph.get("authorized_tools", [])
    authorized_emp_ids = authorization_graph.get("authorized_employee_ids", [])

    # Tool not in auth graph
    if tool_name not in authorized_tools and authorization_graph:
        # Authorization graph was built — tool wasn't in user's intent
        return {
            "authorized": False,
            "reason": f"tool '{tool_name}' not authorized by user intent (auth_graph mismatch)",
        }

    # For lookup_employee: check employee ID authorization
    if tool_name == "lookup_employee":
        requested_id = str(arguments.get("employee_id", "")).upper()
        if authorized_emp_ids and requested_id not in authorized_emp_ids:
            return {
                "authorized": False,
                "reason": (
                    f"employee_id '{requested_id}' not mentioned in user request "
                    f"(authorized: {authorized_emp_ids})"
                ),
            }

    return {"authorized": True, "reason": "authorization_check_passed"}


def broker_check(
    tool_name: str,
    arguments: Dict[str, Any],
    user_input: str,
    authorization_graph: Dict[str, Any],
    tool_source: str = "planner",
    messages: Optional[List[Dict[str, str]]] = None,
) -> Dict[str, Any]:
    """
    Main broker decision function.

    Returns: {decision: ALLOW|DENY|REDACT, reason, provenance_check, auth_check}
    """
    messages = messages or []

    # 1. Allow-list check
    if tool_name not in _TOOL_ALLOWLIST:
        return {
            "decision": "DENY",
            "reason": f"tool '{tool_name}' not in allow-list",
            "control": "allowlist",
        }

    # 2. Source provenance check (PACT-style)
    if tool_source in _UNTRUSTED_SOURCES and tool_name in _SENSITIVE_TOOLS:
        return {
            "decision": "DENY",
            "reason": (
                f"sensitive tool '{tool_name}' called from untrusted source '{tool_source}'. "
                f"This is the EchoLeak-class indirect injection pattern — "
                f"the instruction to call this tool originated from document/injected content, "
                f"not from the user."
            ),
            "control": "provenance",
            "provenance_source": tool_source,
        }

    # 3. Taint analysis on arguments
    taints = _taint_analysis(tool_name, arguments, messages, tool_source, user_input)
    authority_args = _AUTHORITY_ARGS.get(tool_name, [])

    for arg_name in authority_args:
        if arg_name in taints:
            taint_info = taints[arg_name]
            if taint_info["taint"] == "injected":
                return {
                    "decision": "DENY",
                    "reason": (
                        f"authority-bearing argument '{arg_name}' traces to injected/untrusted content. "
                        f"PACT-style block: argument value '{taint_info['value']}' "
                        f"originates from injection, not user request."
                    ),
                    "control": "argument_provenance",
                    "taint_analysis": taints,
                }

    # 4. AuthGraph check (only if authorization_graph was built)
    if authorization_graph:
        auth_result = _authorization_check(tool_name, arguments, authorization_graph, user_input)
        if not auth_result["authorized"]:
            return {
                "decision": "DENY",
                "reason": auth_result["reason"],
                "control": "authorization_graph",
                "auth_check": auth_result,
            }

    # 5. Argument validation
    if tool_name == "lookup_employee":
        emp_id = str(arguments.get("employee_id", ""))
        # Block bulk enumeration attempts
        if "*" in emp_id or "%" in emp_id:
            return {
                "decision": "DENY",
                "reason": f"bulk enumeration attempt blocked: employee_id='{emp_id}'",
                "control": "argument_validation",
            }
        if not re.match(r"^EMP-\d{3}$", emp_id.upper()):
            return {
                "decision": "DENY",
                "reason": f"invalid employee_id format: '{emp_id}'",
                "control": "argument_validation",
            }

    # 6. ALLOW
    return {
        "decision": "ALLOW",
        "reason": "all broker checks passed",
        "control": "none",
        "taint_analysis": taints,
    }
