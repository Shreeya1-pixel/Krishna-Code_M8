"""
Deterministic LoRA retraining plan generator.
Does NOT train anything — produces a safe-to-display plan artifact.
LoRA retraining-plan controller for M8.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, List


def generate_lora_plan(
    missed_attacks: List[Dict[str, Any]],
    current_asr: float,
    target_asr: float = 0.10,
) -> Dict[str, Any]:
    """
    Generate a deterministic LoRA retraining plan from missed attacks.
    Returns a plan dict — does not actually train anything.
    """
    n = len(missed_attacks)

    # Compute plan hash (deterministic from inputs)
    seed = json.dumps({"attacks": [a.get("id", "") for a in missed_attacks], "asr": current_asr}, sort_keys=True)
    plan_hash = hashlib.sha256(seed.encode()).hexdigest()[:16]

    # Hyperparameters (deterministic based on data size)
    lora_r = 8 if n < 20 else 16
    lora_alpha = lora_r * 2
    learning_rate = 2e-4 if n < 10 else 1e-4
    epochs = max(3, min(10, n // 2))
    batch_size = min(8, max(2, n // 4))

    # Training samples from missed attacks
    training_samples = []
    for attack in missed_attacks[:50]:  # cap at 50
        training_samples.append({
            "input": attack.get("payload", attack.get("user_query", ""))[:200],
            "label": "threat",
            "attack_id": attack.get("id", ""),
            "category": attack.get("category", "unknown"),
        })

    # Safety checks
    safe_to_deploy = (
        n >= 5 and  # enough data
        current_asr > target_asr and  # actually needs improvement
        len(set(a.get("category") for a in missed_attacks)) >= 2  # diverse categories
    )

    return {
        "plan_id": f"lora-plan-{plan_hash}",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "trigger": "missed_attacks",
        "missed_attack_count": n,
        "current_asr": round(current_asr, 3),
        "target_asr": target_asr,
        "hyperparameters": {
            "base_model": "distilbert-base-uncased",
            "lora_r": lora_r,
            "lora_alpha": lora_alpha,
            "lora_dropout": 0.05,
            "learning_rate": learning_rate,
            "epochs": epochs,
            "batch_size": batch_size,
            "max_length": 128,
            "warmup_ratio": 0.1,
            "weight_decay": 0.01,
        },
        "training_samples": training_samples[:10],  # show first 10 for display
        "training_sample_count": len(training_samples),
        "estimated_training_time_mins": max(5, n * 2),
        "safe_to_deploy": safe_to_deploy,
        "safe_to_deploy_reason": (
            "Sufficient diverse missed attacks for training" if safe_to_deploy
            else f"Need ≥5 missed attacks from ≥2 categories (have {n} from {len(set(a.get('category') for a in missed_attacks))} categories)"
        ),
        "deployment_steps": [
            "1. Review training samples for quality",
            "2. Run fine-tuning job (estimated time above)",
            "3. Evaluate on held-out test set (target: ASR < " + str(target_asr) + ")",
            "4. A/B test against current model for 24h",
            "5. Deploy if metrics improve without utility regression",
        ],
        "residual_risks": [
            "LoRA fine-tuning may overfit to seen attack patterns",
            "Novel attack variants not in training data remain a risk",
            "Utility (task completion rate) should be measured alongside ASR",
            "Model drift may require periodic retraining",
        ],
    }
