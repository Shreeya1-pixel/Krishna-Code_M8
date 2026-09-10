"""Tests for policy broker."""
import pytest
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from backend.defenses.policy_broker import broker_check


def test_allows_legitimate_read():
    result = broker_check(
        tool_name="read_document",
        arguments={"filename": "company_policy.txt"},
        user_input="Please summarize the company policy document",
        authorization_graph={"authorized_tools": ["read_document"], "authorized_employee_ids": [], "is_document_requested": True},
        tool_source="planner",
    )
    assert result["decision"] == "ALLOW"


def test_denies_unlisted_tool():
    result = broker_check(
        tool_name="send_email",
        arguments={"to": "attacker@evil.com"},
        user_input="send email",
        authorization_graph={},
        tool_source="planner",
    )
    assert result["decision"] == "DENY"
    assert "allow-list" in result["reason"]


def test_denies_injected_lookup():
    result = broker_check(
        tool_name="lookup_employee",
        arguments={"employee_id": "EMP-001"},
        user_input="please summarize the invoice",
        authorization_graph={"authorized_tools": [], "authorized_employee_ids": []},
        tool_source="injected_instruction",
    )
    assert result["decision"] == "DENY"
    assert "provenance" in result["reason"] or "source" in result["reason"]


def test_denies_wildcard_employee_id():
    result = broker_check(
        tool_name="lookup_employee",
        arguments={"employee_id": "*"},
        user_input="get all employees",
        authorization_graph={},
        tool_source="planner",
    )
    assert result["decision"] == "DENY"


def test_denies_unauthorized_lookup():
    result = broker_check(
        tool_name="lookup_employee",
        arguments={"employee_id": "EMP-001"},
        user_input="just summarize the document for me",
        authorization_graph={"authorized_tools": ["read_document"], "authorized_employee_ids": []},
        tool_source="planner",
    )
    assert result["decision"] == "DENY"
