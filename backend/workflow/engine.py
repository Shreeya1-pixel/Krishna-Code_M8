"""
Post-run workflow pipeline.

1. Triage findings by severity
2. Gate decision (CI use case)
3. Build Slack/Jira payloads
4. Regression tracking vs last run
"""
from __future__ import annotations

import os
from typing import Any, Dict, List, Optional, Tuple

from ..store.db import (
    get_run, get_run_attacks, get_last_completed_run,
    save_workflow_result, save_workflow_event,
)
from .integrations.slack import build_slack_payload, send_slack
from .integrations.jira import build_jira_issue, send_jira

GATE_FAIL_ON_CRITICAL = os.getenv("SENTINEL_GATE_FAIL_ON_CRITICAL", "true").lower() == "true"
GATE_MAX_ASR = float(os.getenv("SENTINEL_GATE_MAX_ASR", "0.20"))


def triage_findings(attacks: List[Dict]) -> Dict[str, List[Dict]]:
    """Sort findings by severity."""
    critical, high, medium, low = [], [], [], []
    for a in attacks:
        if a.get("result") == "BLOCKED":
            continue
        sev = a.get("severity", "LOW")
        entry = {
            "attack_id": a.get("attack_id"),
            "category": a.get("category"),
            "severity": sev,
            "result": a.get("result"),
            "reason": a.get("reason", ""),
            "oracle_ref": a.get("oracle_ref", ""),
        }
        if sev == "CRITICAL":
            critical.append(entry)
        elif sev == "HIGH":
            high.append(entry)
        elif sev == "MEDIUM":
            medium.append(entry)
        else:
            low.append(entry)
    return {"CRITICAL": critical, "HIGH": high, "MEDIUM": medium, "LOW": low}


def compute_gate(run: Dict, attacks: List[Dict]) -> Tuple[str, List[str]]:
    """Compute CI gate verdict."""
    reasons = []
    status = "PASS"

    asr = run.get("asr", 0.0)
    succeeded = [a for a in attacks if a.get("result") == "SUCCEEDED"]
    critical_succeeded = [a for a in succeeded if a.get("severity") == "CRITICAL"]

    if GATE_FAIL_ON_CRITICAL and critical_succeeded:
        reasons.append(
            f"CRITICAL attacks succeeded: {[a['attack_id'] for a in critical_succeeded]}"
        )
        status = "FAIL"

    if asr > GATE_MAX_ASR:
        reasons.append(
            f"ASR {asr:.1%} exceeds threshold {GATE_MAX_ASR:.1%}"
        )
        status = "FAIL"

    if not reasons:
        reasons.append(f"All gates passed. ASR {asr:.1%} ≤ {GATE_MAX_ASR:.1%}, no CRITICAL attacks succeeded.")

    return status, reasons


def compute_regression(run: Dict, attacks: List[Dict]) -> Dict[str, Any]:
    """Compare this run against the last run of the same mode."""
    mode = run.get("mode", "defended")
    last_run = get_last_completed_run(mode)

    if not last_run or last_run.get("id") == run.get("id"):
        return {
            "has_baseline": False,
            "message": "No previous run to compare against",
        }

    last_attacks = get_run_attacks(last_run["id"])
    last_succeeded_ids = {a["attack_id"] for a in last_attacks if a.get("result") == "SUCCEEDED"}
    current_succeeded_ids = {a["attack_id"] for a in attacks if a.get("result") == "SUCCEEDED"}

    new_exploits = list(current_succeeded_ids - last_succeeded_ids)
    fixed_exploits = list(last_succeeded_ids - current_succeeded_ids)
    regressed = list(current_succeeded_ids & last_succeeded_ids)

    asr_change = run.get("asr", 0) - last_run.get("asr", 0)

    return {
        "has_baseline": True,
        "baseline_run_id": last_run["id"],
        "baseline_asr": last_run.get("asr", 0),
        "current_asr": run.get("asr", 0),
        "asr_change": round(asr_change, 3),
        "new_exploits": new_exploits,
        "fixed_exploits": fixed_exploits,
        "regressed": regressed,
        "summary": (
            f"{len(new_exploits)} new exploit(s), "
            f"{len(fixed_exploits)} fixed, "
            f"{len(regressed)} persisted"
        ),
    }


async def run_workflow(run_id: str) -> Dict[str, Any]:
    """
    Execute the full post-run workflow pipeline.
    Returns a summary dict with gate verdict + integration results.
    """
    run = get_run(run_id)
    if not run:
        return {"error": f"Run {run_id} not found"}

    attacks = get_run_attacks(run_id)

    # 1. Triage
    triage = triage_findings(attacks)
    save_workflow_event(run_id, "triage", {"findings_by_severity": {
        k: len(v) for k, v in triage.items()
    }})

    # 2. Gate decision
    gate_status, gate_reasons = compute_gate(run, attacks)
    save_workflow_event(run_id, "gate_decision", {
        "status": gate_status, "reasons": gate_reasons
    })

    # 3. Regression
    regression = compute_regression(run, attacks)
    save_workflow_event(run_id, "regression", regression)

    # 4. Slack + Jira for CRITICAL/HIGH findings
    slack_payload = None
    jira_payloads = []
    slack_result = None
    jira_results = []

    critical_findings = triage.get("CRITICAL", []) + triage.get("HIGH", [])

    if critical_findings or gate_status == "FAIL":
        # Build attack details for Slack
        slack_findings = []
        for finding in critical_findings[:5]:
            attack = next((a for a in attacks if a.get("attack_id") == finding["attack_id"]), {})
            slack_findings.append({
                **finding,
                "mitre": [],
                "oracle_ref": attack.get("oracle_ref", ""),
            })

        slack_payload = build_slack_payload(
            run_id=run_id,
            gate_status=gate_status,
            critical_findings=slack_findings,
            asr_before=run.get("asr", 0),
            asr_after=run.get("asr", 0),
            mode=run.get("mode", "defended"),
        )
        slack_result = await send_slack(slack_payload)
        slack_payload["_mock"] = slack_result.get("status") == "mock"
        slack_payload["_delivery_status"] = slack_result.get("status", "unknown")
        slack_payload["_delivery_message"] = slack_result.get("message", "")
        save_workflow_event(run_id, "slack_notification", {
            "status": slack_result.get("status"),
            "payload_preview": str(slack_payload)[:200],
        })

        # Jira for the most urgent findings so the demo shows remediation work even
        # when defended mode downgrades successful attacks from CRITICAL to HIGH.
        for finding in critical_findings[:3]:  # Cap at 3
            attack = next((a for a in attacks if a.get("attack_id") == finding["attack_id"]), {})
            transcript = attack.get("transcript_json") or {}
            jira_payload = build_jira_issue(
                run_id=run_id,
                attack_id=finding["attack_id"],
                category=finding["category"],
                severity=finding["severity"],
                reason=finding["reason"],
                mitre_tags=[],
                remediation_ids=[],
                transcript_summary=str(transcript)[:300],
            )
            jira_result = await send_jira(jira_payload)
            jira_payload["_mock"] = jira_result.get("status") == "mock"
            jira_payload["_delivery_status"] = jira_result.get("status", "unknown")
            jira_payload["_delivery_message"] = jira_result.get("message", "")
            if jira_result.get("issue_key"):
                jira_payload["_issue_key"] = jira_result["issue_key"]
            jira_payloads.append(jira_payload)
            jira_results.append(jira_result)

        save_workflow_event(run_id, "jira_tickets", {
            "count": len(jira_results),
            "results": jira_results,
        })

    # 5. Save workflow result
    save_workflow_result(
        run_id=run_id,
        gate_status=gate_status,
        gate_reasons=gate_reasons,
        slack_payload=slack_payload,
        jira_payload=jira_payloads[0] if jira_payloads else None,
        regression=regression,
    )

    return {
        "run_id": run_id,
        "gate_status": gate_status,
        "gate_reasons": gate_reasons,
        "triage_summary": {k: len(v) for k, v in triage.items()},
        "slack_result": slack_result,
        "jira_count": len(jira_results),
        "regression": regression,
    }
