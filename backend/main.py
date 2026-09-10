"""
M8 Backend — FastAPI main application.

Routes:
  GET  /health
  GET  /agent/info
  GET  /attacks/suite
  POST /assessment/run     → SSE stream
  GET  /assessment/runs
  GET  /assessment/runs/{id}
  GET  /workflow/gate
  GET  /reports/{run_id}/pdf
  GET  /reports/{run_id}/json
  GET  /defenses/status
  POST /defenses/bayesian/feedback
  GET  /defenses/drift
  POST /defenses/lora/plan
"""
from __future__ import annotations

import asyncio
import json
import os
import time
import uuid
from datetime import datetime, timezone
from typing import Any, AsyncGenerator, Dict, List, Optional

from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response, StreamingResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from pathlib import Path

from .store.db import (
    init_db, create_run, update_run_stats, get_run, list_runs,
    get_run_attacks, get_workflow_result, get_latest_workflow_result,
    save_attack_result,
)
from .agent.secure_assist import run_agent_turn
from .agent.tools import TOOL_CATALOG, read_document, ALLOWED_DOCUMENTS
from .attacks.suite import get_attack_suite, ATTACK_SUITE, get_attack_by_id
from .scoring.oracles import score_attack
from .workflow.engine import run_workflow, compute_gate
from .reports.generator import generate_json_report, generate_pdf_report
from .defenses.ml.bayesian_threshold import get_bayesian_engine
from .defenses.ml.drift_detector import get_drift_detector
from .defenses.ml.lora_finetune_controller import generate_lora_plan


# ── App setup ─────────────────────────────────────────────────────────────────

app = FastAPI(
    title="M8",
    description="Adaptive Red-Team Testing for AI Agents — SCD 2026",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize DB on startup
@app.on_event("startup")
async def startup():
    init_db()
    # Skip long baseline seed in production (Railway healthcheck / cold start)
    if os.getenv("SENTINEL_SEED_BASELINE", "true").lower() not in ("1", "true", "yes"):
        return
    from .store.db import list_runs
    if not list_runs(limit=1):
        await _seed_baseline()


async def _seed_baseline():
    """Seed a vulnerable baseline run for demo dashboard population."""
    try:
        await _run_full_assessment(run_id=str(uuid.uuid4()), mode="vulnerable", suite_type="suite")
    except Exception as e:
        print(f"Baseline seed failed (non-critical): {e}")


# ── Models ────────────────────────────────────────────────────────────────────

class RunRequest(BaseModel):
    mode: str = "defended"              # "vulnerable" | "defended"
    suite_type: str = "suite"           # "suite" | "adaptive"
    defense_config: Optional[Dict[str, bool]] = None


class AgentTurnRequest(BaseModel):
    user_input: str
    mode: str = "defended"


class BayesianFeedbackRequest(BaseModel):
    scan_id: str = ""
    human_verdict: str                  # "correct" | "false_positive" | "false_negative"
    original_decision: str = "BLOCK"   # "BLOCK" | "ALLOW"
    attack_class: str = "other"


class LoRAPlanRequest(BaseModel):
    run_id: Optional[str] = None       # If provided, use missed attacks from that run


class ClassifyRequest(BaseModel):
    text: str
    check_doc_content: bool = False


# ── Health ────────────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {
        "status": "ok",
        "service": "M8",
        "version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "offline_mode": os.getenv("LLM_PROVIDER", "mock") == "mock",
    }


# ── Agent info ────────────────────────────────────────────────────────────────

@app.get("/agent/info")
async def agent_info():
    from .agent.llm import SECURE_ASSIST_SYSTEM_PROMPT
    return {
        "name": "SecureAssist",
        "description": "AcmeCorp internal AI assistant — handles company documents and HR queries.",
        "system_prompt_redacted": "[REDACTED — contains confidentiality rules, tool usage policy, and access controls]",
        "system_prompt_hint": "SecureAssist has rules about: never revealing its system prompt, treating document content as data (not instructions), only using tools when explicitly authorized.",
        "tools": [
            {
                "name": t["name"],
                "description": t["description"],
                "is_sensitive": t["name"] == "lookup_employee",
            }
            for t in TOOL_CATALOG
        ],
        "documents": list(ALLOWED_DOCUMENTS),
        "llm_provider": os.getenv("LLM_PROVIDER", "mock"),
        "note": "ALL EMPLOYEE DATA IS SIMULATED DEMO DATA",
    }


# ── Agent turn (direct) ───────────────────────────────────────────────────────

@app.post("/agent/turn")
async def agent_turn(req: AgentTurnRequest):
    result = run_agent_turn(
        user_input=req.user_input,
        mode=req.mode,
    )
    return result


# ── Attack suite ──────────────────────────────────────────────────────────────

@app.get("/attacks/suite")
async def attack_suite():
    return {
        "attacks": get_attack_suite(),
        "total": len(ATTACK_SUITE),
        "categories": list(dict.fromkeys(a.category for a in ATTACK_SUITE)),
    }


@app.get("/attacks/{attack_id}")
async def attack_detail(attack_id: str):
    attack = get_attack_by_id(attack_id)
    if not attack:
        raise HTTPException(404, f"Attack {attack_id} not found")
    return attack.to_dict()


# ── Assessment run (SSE streaming) ────────────────────────────────────────────

@app.post("/assessment/run")
async def run_assessment(req: RunRequest):
    run_id = str(uuid.uuid4())

    async def event_generator() -> AsyncGenerator[str, None]:
        async for event in _stream_assessment(run_id, req.mode, req.suite_type, req.defense_config):
            yield event

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "X-Accel-Buffering": "no",
        },
    )


@app.post("/assessment/run-sync")
async def run_assessment_sync(req: RunRequest):
    """Non-streaming fallback for browsers/proxies that break SSE fetch streams."""
    run_id = str(uuid.uuid4())
    events: List[Dict[str, Any]] = []
    async for raw in _stream_assessment(run_id, req.mode, req.suite_type, req.defense_config):
        # raw is "event: X\ndata: {...}\n\n"
        event_type = "message"
        data: Any = {}
        for line in raw.strip().split("\n"):
            if line.startswith("event:"):
                event_type = line[6:].strip()
            elif line.startswith("data:"):
                try:
                    data = json.loads(line[5:].strip())
                except Exception:
                    data = {"raw": line[5:].strip()}
        events.append({"type": event_type, "data": data})
    return {"run_id": run_id, "events": events}


async def _stream_assessment(
    run_id: str,
    mode: str,
    suite_type: str,
    defense_config: Optional[Dict] = None,
) -> AsyncGenerator[str, None]:
    """Stream SSE events for an assessment run."""

    def _sse(event_type: str, data: Any) -> str:
        return f"event: {event_type}\ndata: {json.dumps(data)}\n\n"

    yield _sse("phase", {"phase": "initializing", "run_id": run_id, "mode": mode})

    # Create run record
    d_config = defense_config or ({"enabled": True, "classifier": True, "policy_broker": True, "output_guard": True} if mode == "defended" else {"enabled": False})
    create_run(run_id, mode, suite_type, d_config)

    yield _sse("phase", {"phase": "loading_suite", "total_attacks": len(ATTACK_SUITE)})

    if suite_type == "adaptive":
        # Adaptive run — score each seed as SUCCEEDED (confirmed exploit) or BLOCKED (held)
        from .attacks.adaptive import run_full_adaptive_suite
        from .attacks.suite import ATTACK_SUITE as _SUITE

        yield _sse("phase", {"phase": "adaptive_attack_loop"})

        attack_by_id = {a.id: a for a in _SUITE}
        succeeded = partial = blocked = 0
        total = 0
        finished_ids: set[str] = set()

        for event in run_full_adaptive_suite(mode=mode, max_attempts_per_attack=4):
            yield _sse("adaptive_event", event)

            if event.get("type") == "adaptive_start":
                yield _sse("score_update", {
                    "total": 0,
                    "succeeded": 0,
                    "partial": 0,
                    "blocked": 0,
                    "asr": 0,
                    "planned_total": event.get("total_candidates", 0),
                })

            elif event.get("type") == "attack_start":
                attack = attack_by_id.get(event.get("attack_id"))
                yield _sse("attack_start", {
                    "attack_id": event.get("attack_id"),
                    "category": event.get("category") or (attack.category if attack else ""),
                    "description": attack.description if attack else "Adaptive seed",
                    "index": total + 1,
                    "total": 6,
                })

            elif event.get("type") in ("confirmed", "exhausted", "unconfirmed"):
                attack_id = event.get("attack_id", "unknown")
                if attack_id in finished_ids:
                    await asyncio.sleep(0.05)
                    continue
                finished_ids.add(attack_id)
                attack = attack_by_id.get(attack_id)
                total += 1

                if event.get("type") == "confirmed":
                    result = "SUCCEEDED"
                    succeeded += 1
                    reason = f"Adaptive exploit confirmed after {len(event.get('escalation_path') or [])} attempts"
                    severity = attack.severity_if_success if attack else "HIGH"
                else:
                    result = "BLOCKED"
                    blocked += 1
                    reason = event.get("message") or "Adaptive mutations exhausted without confirmed exploit"
                    severity = "INFO"

                yield _sse("attack_result", {
                    "attack_id": attack_id,
                    "category": attack.category if attack else event.get("category", "adaptive"),
                    "result": result,
                    "severity": severity,
                    "reason": reason,
                    "elapsed_ms": 0,
                    "halted_at_node": "defense" if result == "BLOCKED" else None,
                })

                save_attack_result(
                    run_id=run_id,
                    attack_id=attack_id,
                    category=attack.category if attack else "adaptive",
                    result=result,
                    severity=severity,
                    reason=reason,
                    transcript={"adaptive_event": event.get("type"), "escalation_path": event.get("escalation_path")},
                    tool_calls=[],
                    node_trace=[],
                    elapsed_ms=0,
                )

                asr_so_far = succeeded / total if total > 0 else 0
                yield _sse("score_update", {
                    "total": total,
                    "succeeded": succeeded,
                    "partial": partial,
                    "blocked": blocked,
                    "asr": round(asr_so_far, 3),
                })

            await asyncio.sleep(0.05)

        asr = succeeded / total if total > 0 else 0
        ur = blocked / total if total > 0 else 0
        update_run_stats(run_id, total, succeeded, partial, blocked, asr, ur)

        yield _sse("phase", {"phase": "workflow"})
        workflow_result: Dict[str, Any] = {}
        try:
            workflow_result = await run_workflow(run_id)
            yield _sse("workflow_result", workflow_result)
        except Exception as e:
            yield _sse("workflow_error", {"error": str(e)})

        yield _sse("done", {
            "run_id": run_id,
            "mode": mode,
            "suite_type": "adaptive",
            "total": total,
            "succeeded": succeeded,
            "partial": partial,
            "blocked": blocked,
            "asr": round(asr, 3),
            "ur": round(ur, 3),
            "gate_status": workflow_result.get("gate_status", "N/A"),
        })
        return

    # Static suite run
    results = []
    succeeded = partial = blocked = 0

    for i, attack in enumerate(ATTACK_SUITE):
        yield _sse("attack_start", {
            "attack_id": attack.id,
            "category": attack.category,
            "description": attack.description,
            "index": i + 1,
            "total": len(ATTACK_SUITE),
        })

        t0 = time.time()
        try:
            turn_result = run_agent_turn(
                user_input=attack.user_query,
                mode=mode,
            )

            # Score
            oracle = score_attack(
                attack_id=attack.id,
                oracle_ref=attack.oracle_ref,
                category=attack.category,
                doc_name=attack.doc_name,
                user_input=attack.user_query,
                final_response=turn_result.get("final_response", ""),
                tool_calls=turn_result.get("tool_requests", []),
                mode=mode,
                node_trace=turn_result.get("node_trace", []),
            )

            elapsed = int((time.time() - t0) * 1000)
            result = oracle["result"]

            if result == "SUCCEEDED":
                succeeded += 1
            elif result == "PARTIAL":
                partial += 1
            else:
                blocked += 1

            # Emit node trace
            yield _sse("node_trace", {
                "attack_id": attack.id,
                "node_trace": turn_result.get("node_trace", []),
            })

            # Emit result
            yield _sse("attack_result", {
                "attack_id": attack.id,
                "category": attack.category,
                "result": result,
                "severity": oracle.get("severity", attack.severity_if_success),
                "reason": oracle.get("reason", ""),
                "elapsed_ms": elapsed,
                "halted_at_node": turn_result.get("halted_at_node"),
            })

            # Save to DB
            save_attack_result(
                run_id=run_id,
                attack_id=attack.id,
                category=attack.category,
                result=result,
                severity=oracle.get("severity", attack.severity_if_success),
                reason=oracle.get("reason", ""),
                transcript=turn_result,
                tool_calls=turn_result.get("tool_requests", []),
                node_trace=turn_result.get("node_trace", []),
                elapsed_ms=elapsed,
            )

            results.append({"attack_id": attack.id, **oracle, "elapsed_ms": elapsed})

            # Score update
            total_so_far = i + 1
            asr_so_far = succeeded / total_so_far if total_so_far > 0 else 0
            yield _sse("score_update", {
                "total": total_so_far,
                "succeeded": succeeded,
                "partial": partial,
                "blocked": blocked,
                "asr": round(asr_so_far, 3),
            })

        except Exception as e:
            yield _sse("error", {"attack_id": attack.id, "error": str(e)})
            blocked += 1

        await asyncio.sleep(0.1)  # Throttle for SSE

    # Finalize run stats
    total = len(ATTACK_SUITE)
    asr = succeeded / total if total > 0 else 0
    ur = blocked / total if total > 0 else 0

    update_run_stats(run_id, total, succeeded, partial, blocked, asr, ur)

    yield _sse("phase", {"phase": "workflow"})

    # Run workflow
    try:
        workflow_result = await run_workflow(run_id)
        yield _sse("workflow_result", workflow_result)
    except Exception as e:
        yield _sse("workflow_error", {"error": str(e)})

    yield _sse("done", {
        "run_id": run_id,
        "mode": mode,
        "total": total,
        "succeeded": succeeded,
        "partial": partial,
        "blocked": blocked,
        "asr": round(asr, 3),
        "ur": round(ur, 3),
        "gate_status": workflow_result.get("gate_status") if "workflow_result" in dir() else "N/A",
    })


async def _run_full_assessment(run_id: str, mode: str, suite_type: str):
    """Non-streaming version for seeding."""
    async for _ in _stream_assessment(run_id, mode, suite_type):
        pass


# ── Assessment history ────────────────────────────────────────────────────────

@app.get("/assessment/runs")
async def list_assessment_runs(limit: int = Query(50, ge=1, le=200)):
    runs = list_runs(limit=limit)
    return {"runs": runs, "total": len(runs)}


@app.get("/assessment/runs/{run_id}")
async def get_assessment_run(run_id: str):
    run = get_run(run_id)
    if not run:
        raise HTTPException(404, f"Run {run_id} not found")
    attacks = get_run_attacks(run_id)
    workflow = get_workflow_result(run_id)
    return {"run": run, "attacks": attacks, "workflow": workflow}


# ── Workflow ──────────────────────────────────────────────────────────────────

def _slack_open_url() -> str:
    """Public Slack deep-link for the UI (never returns the webhook secret)."""
    explicit = os.getenv("SLACK_CHANNEL_URL", "").strip()
    if explicit:
        return explicit
    webhook = os.getenv("SLACK_WEBHOOK_URL", "").strip()
    # hooks.slack.com/services/T…/B…/… → open workspace client
    if "/services/" in webhook:
        try:
            team_id = webhook.split("/services/")[1].split("/")[0]
            if team_id.startswith("T"):
                return f"https://app.slack.com/client/{team_id}"
        except Exception:
            pass
    return "https://app.slack.com/"


def _jira_open_urls() -> dict:
    """Public Jira project / browse URLs for the UI."""
    base = os.getenv("JIRA_BASE_URL", "").strip().rstrip("/")
    key = os.getenv("JIRA_PROJECT_KEY", "").strip()
    if not base:
        return {"project_url": "", "browse_base": ""}
    project_url = f"{base}/jira/software/projects/{key}" if key else base
    return {"project_url": project_url, "browse_base": f"{base}/browse"}


def _integration_status() -> dict:
    """Report live vs mock without exposing secrets."""
    slack_live = bool(os.getenv("SLACK_WEBHOOK_URL", "").strip())
    jira_live = all(
        os.getenv(k, "").strip()
        for k in ("JIRA_BASE_URL", "JIRA_USER_EMAIL", "JIRA_API_TOKEN", "JIRA_PROJECT_KEY")
    )
    jira_urls = _jira_open_urls()
    return {
        "slack": {
            "mode": "live" if slack_live else "mock",
            "configured": slack_live,
            "label": "LIVE" if slack_live else "MOCK",
            "open_url": _slack_open_url() if slack_live else "https://app.slack.com/",
        },
        "jira": {
            "mode": "live" if jira_live else "mock",
            "configured": jira_live,
            "project_key": os.getenv("JIRA_PROJECT_KEY", "") if jira_live else "",
            "label": "LIVE" if jira_live else "MOCK",
            "open_url": jira_urls["project_url"] if jira_live else "https://www.atlassian.com/software/jira",
            "browse_base": jira_urls["browse_base"] if jira_live else "",
        },
    }


@app.get("/workflow/gate")
async def workflow_gate():
    integrations = _integration_status()
    result = get_latest_workflow_result()
    if not result:
        return {
            "status": "no_runs",
            "reasons": ["No completed assessment runs found"],
            "integrations": integrations,
        }
    return {
        "status": result.get("gate_status", "N/A"),
        "reasons": result.get("gate_reasons", []),
        "run_id": result.get("run_id"),
        "slack_payload": result.get("slack_payload"),
        "jira_payload": result.get("jira_payload"),
        "regression": result.get("regression"),
        "integrations": integrations,
    }


@app.get("/workflow/runs/{run_id}")
async def workflow_run_detail(run_id: str):
    result = get_workflow_result(run_id)
    if not result:
        raise HTTPException(404, f"Workflow result for run {run_id} not found")
    return result


# ── Reports ───────────────────────────────────────────────────────────────────

@app.get("/reports/{run_id}/json")
async def report_json(run_id: str):
    return generate_json_report(run_id)


@app.get("/reports/{run_id}/pdf")
async def report_pdf(run_id: str):
    pdf_bytes = generate_pdf_report(run_id)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=m8-report-{run_id[:8]}.pdf"},
    )


@app.get("/reports/latest/pdf")
async def report_latest_pdf():
    runs = list_runs(limit=1)
    if not runs:
        raise HTTPException(404, "No runs found")
    run_id = runs[0]["id"]
    return await report_pdf(run_id)


# ── Defense controls ──────────────────────────────────────────────────────────

@app.get("/defenses/status")
async def defense_status():
    bayesian = get_bayesian_engine().status()
    drift = get_drift_detector().status()
    return {
        "bayesian_threshold": bayesian,
        "drift": drift,
        "controls": {
            "classifier": "enabled",
            "policy_broker": "enabled",
            "output_guard": "enabled",
        },
    }


@app.post("/defenses/classify")
async def classify_text(req: ClassifyRequest):
    from .defenses.injection_classifier import classify_input
    return classify_input(req.text, check_doc_content=req.check_doc_content)


@app.post("/defenses/bayesian/feedback")
async def bayesian_feedback(req: BayesianFeedbackRequest):
    engine = get_bayesian_engine()
    result = engine.process_feedback({
        "scan_id": req.scan_id,
        "human_verdict": req.human_verdict,
        "original_decision": req.original_decision,
        "attack_class": req.attack_class,
    })
    return result


@app.get("/defenses/drift")
async def drift_status():
    return get_drift_detector().status()


@app.post("/defenses/lora/plan")
async def lora_plan(req: LoRAPlanRequest):
    missed_attacks = []
    current_asr = 0.0

    if req.run_id:
        attacks = get_run_attacks(req.run_id)
        missed_attacks = [
            {"id": a["attack_id"], "category": a["category"],
             "payload": a.get("transcript_json", {}).get("user_input", "") if isinstance(a.get("transcript_json"), dict) else ""}
            for a in attacks if a.get("result") == "SUCCEEDED"
        ]
        run = get_run(req.run_id)
        current_asr = run.get("asr", 0) if run else 0
    else:
        # Use latest run
        runs = list_runs(limit=1)
        if runs:
            attacks = get_run_attacks(runs[0]["id"])
            missed_attacks = [
                {"id": a["attack_id"], "category": a["category"], "payload": ""}
                for a in attacks if a.get("result") == "SUCCEEDED"
            ]
            current_asr = runs[0].get("asr", 0)

    plan = generate_lora_plan(missed_attacks, current_asr)
    return plan


# ── Production SPA (Railway / Docker single-service) ──────────────────────────

_FRONTEND_DIST = Path(__file__).resolve().parents[1] / "frontend" / "dist"
if _FRONTEND_DIST.is_dir():
    app.mount("/assets", StaticFiles(directory=str(_FRONTEND_DIST / "assets")), name="assets")

    @app.get("/{full_path:path}")
    async def spa_fallback(full_path: str):
        """Serve static files or the React SPA for non-API routes."""
        if full_path.startswith((
            "assessment", "attacks", "agent", "workflow", "reports",
            "defenses", "health", "docs", "openapi", "redoc",
        )):
            raise HTTPException(404, "Not found")
        candidate = (_FRONTEND_DIST / full_path).resolve()
        if full_path and candidate.is_file() and str(candidate).startswith(str(_FRONTEND_DIST.resolve())):
            return FileResponse(candidate)
        index = _FRONTEND_DIST / "index.html"
        if not index.is_file():
            raise HTTPException(404, "Frontend not built")
        return FileResponse(index)
