"""
SecureAssist orchestrator — runs a full agent turn using graph.py.
"""
from __future__ import annotations

import uuid
from typing import Any, Dict, Optional

from .graph import TurnState, run_turn, state_to_dict
from .llm import get_llm_client, SECURE_ASSIST_SYSTEM_PROMPT
from .tools import execute_tool
from ..defenses.config import DefenseConfig, get_defense_config


def run_agent_turn(
    user_input: str,
    mode: str = "defended",
    defense_config: Optional[DefenseConfig] = None,
    turn_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Run a single SecureAssist agent turn.

    Args:
        user_input: The user's message
        mode: "vulnerable" | "defended"
        defense_config: Optional per-turn defense config override
        turn_id: Optional turn identifier (generated if not provided)

    Returns:
        Serialized TurnState dict with full node_trace
    """
    if turn_id is None:
        turn_id = str(uuid.uuid4())

    if defense_config is None:
        defense_config = get_defense_config()

    # Get LLM (same MockLLM for both modes — defenses do the work)
    llm = get_llm_client(vulnerable=(mode == "vulnerable"))

    # Build defense function refs based on config
    classifier_fn = None
    broker_fn = None
    guard_fn = None

    if mode == "defended" and defense_config.enabled:
        if defense_config.classifier:
            from ..defenses.injection_classifier import classify_input
            classifier_fn = classify_input

        if defense_config.policy_broker:
            from ..defenses.policy_broker import broker_check
            broker_fn = broker_check

        if defense_config.output_guard:
            from ..defenses.output_guard import guard_output
            guard_fn = guard_output

    # Initialize state
    state = TurnState(
        turn_id=turn_id,
        user_input=user_input,
        mode=mode,
    )

    # Run the graph
    state = run_turn(
        state=state,
        llm_client=llm,
        system_prompt=SECURE_ASSIST_SYSTEM_PROMPT,
        classifier_fn=classifier_fn,
        broker_fn=broker_fn,
        guard_fn=guard_fn,
        tool_executor=execute_tool,
    )

    return state_to_dict(state)
