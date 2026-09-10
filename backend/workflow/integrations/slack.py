"""
Slack integration — builds Block Kit message.
Mock by default; POST if SLACK_WEBHOOK_URL is set.
"""
from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional


SEVERITY_COLORS = {
    "CRITICAL": "#FF0000",
    "HIGH": "#FF6600",
    "MEDIUM": "#FFAA00",
    "LOW": "#00AA00",
}


def build_slack_payload(
    run_id: str,
    gate_status: str,
    critical_findings: List[Dict[str, Any]],
    asr_before: float,
    asr_after: float,
    mode: str,
) -> Dict[str, Any]:
    """Build a Slack Block Kit message payload."""

    # Header
    gate_emoji = "🚨" if gate_status == "FAIL" else "✅"
    gate_color = "#FF0000" if gate_status == "FAIL" else "#00AA00"

    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"{gate_emoji} M8 Security Assessment — CI Gate {gate_status}",
            },
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Run ID:*\n`{run_id[:12]}...`"},
                {"type": "mrkdwn", "text": f"*Mode:*\n{mode.capitalize()}"},
                {"type": "mrkdwn", "text": f"*ASR Before:*\n{asr_before:.1%}"},
                {"type": "mrkdwn", "text": f"*ASR After:*\n{asr_after:.1%}"},
            ],
        },
        {"type": "divider"},
    ]

    # Critical findings
    if critical_findings:
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*🔴 {len(critical_findings)} Critical Finding(s) Require Immediate Attention:*",
            },
        })

        for finding in critical_findings[:5]:  # Cap at 5 in Slack
            mitre = ", ".join(finding.get("mitre", []))
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"*{finding.get('attack_id', 'N/A')}* — {finding.get('category', 'N/A')}\n"
                        f">{finding.get('reason', 'No details')}\n"
                        f"ATLAS: `{mitre or 'N/A'}` | Oracle: `{finding.get('oracle_ref', 'N/A')}`"
                    ),
                },
            })
    else:
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": "✅ *No critical findings in this assessment.*"},
        })

    blocks.extend([
        {"type": "divider"},
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": (
                        "🤖 *M8* — Adaptive Red-Team Testing for AI Agents | "
                        "SCD 2026 | All data is SIMULATED DEMO DATA"
                    ),
                }
            ],
        },
    ])

    return {
        "text": f"M8 CI Gate {gate_status} — {len(critical_findings)} critical findings",
        "attachments": [{"color": gate_color, "blocks": blocks}],
        "_mock": True,
        "_run_id": run_id,
    }


async def send_slack(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Send Slack message. Mock if no webhook URL configured."""
    webhook_url = os.getenv("SLACK_WEBHOOK_URL", "")

    if not webhook_url:
        return {
            "status": "mock",
            "message": "SLACK_WEBHOOK_URL not set — payload stored as mock",
            "payload": payload,
        }

    try:
        import httpx
        outbound_payload = {k: v for k, v in payload.items() if not k.startswith("_")}
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(webhook_url, json=outbound_payload)
            return {
                "status": "sent",
                "http_status": resp.status_code,
                "message": "Slack notification sent",
            }
    except Exception as e:
        return {
            "status": "error",
            "message": str(e),
            "payload": payload,
        }
