"""
Bayesian threshold adaptation engine for M8.
Beta(α,β) adaptive threshold, SQLite-backed, offline deterministic math.
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional, Tuple

logger = logging.getLogger("sentinel.bayesian")

ATTACK_CLASSES = ("direct_injection", "indirect_injection", "tool_misuse", "exfiltration", "multilingual", "other")
PRIOR_ALPHA = float(os.getenv("SENTINEL_BAYESIAN_PRIOR_ALPHA", "4"))
PRIOR_BETA = float(os.getenv("SENTINEL_BAYESIAN_PRIOR_BETA", "2"))
THRESHOLD_FLOOR = 0.45
THRESHOLD_CEILING = 0.90
WARN_THRESHOLD = 0.30
DRIFT_DELTA = 0.05

_threshold_history: Deque[float] = deque(maxlen=10)
_last_update_result: Optional[Dict[str, Any]] = None


def _db_path() -> Path:
    override = os.getenv("SENTINEL_DB_PATH", "./sentinel.db")
    p = Path(override).parent / "sentinel_bayesian.db"
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def _clamp(v: float) -> float:
    return round(max(THRESHOLD_FLOOR, min(THRESHOLD_CEILING, v)), 4)


def _posterior_mean(alpha: float, beta: float) -> float:
    return _clamp(alpha / (alpha + beta))


def _credible_interval(alpha: float, beta: float) -> Tuple[float, float]:
    try:
        from scipy.stats import beta as beta_dist
        lo = float(beta_dist.ppf(0.025, alpha, beta))
        hi = float(beta_dist.ppf(0.975, alpha, beta))
    except Exception:
        mean = alpha / (alpha + beta)
        lo, hi = mean - 0.08, mean + 0.08
    return _clamp(lo), _clamp(hi)


@dataclass
class BetaState:
    alpha: float = PRIOR_ALPHA
    beta: float = PRIOR_BETA
    sample_count: int = 0

    @property
    def threshold(self) -> float:
        return _posterior_mean(self.alpha, self.beta)

    def apply_update(self, verdict: str, decision: str) -> bool:
        verdict = verdict.lower()
        decision = decision.upper()
        if verdict == "correct" and decision == "BLOCK":
            self.alpha += 1; self.sample_count += 1; return True
        if verdict == "false_positive":
            self.beta += 1; self.sample_count += 1; return True
        if verdict == "false_negative" and decision == "ALLOW":
            self.alpha += 2; self.sample_count += 1; return True
        return False


class BayesianThresholdEngine:
    def __init__(self, db_path: Optional[Path] = None):
        self._path = db_path or _db_path()
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self):
        with self._connect() as conn:
            conn.execute("""CREATE TABLE IF NOT EXISTS bayesian_threshold (
              scope TEXT PRIMARY KEY, alpha REAL, beta REAL, sample_count INTEGER, updated_at TEXT
            )""")
            conn.execute("""CREATE TABLE IF NOT EXISTS bayesian_log (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              scan_id TEXT, payload_json TEXT, result_json TEXT, timestamp TEXT
            )""")
            for scope in ("global",) + ATTACK_CLASSES:
                if not conn.execute("SELECT 1 FROM bayesian_threshold WHERE scope=?", (scope,)).fetchone():
                    conn.execute(
                        "INSERT INTO bayesian_threshold VALUES (?,?,?,0,?)",
                        (scope, PRIOR_ALPHA, PRIOR_BETA, datetime.now(timezone.utc).isoformat()),
                    )
            conn.commit()

    def _load(self, scope: str) -> BetaState:
        with self._connect() as conn:
            row = conn.execute("SELECT alpha,beta,sample_count FROM bayesian_threshold WHERE scope=?", (scope,)).fetchone()
        return BetaState(float(row["alpha"]), float(row["beta"]), int(row["sample_count"])) if row else BetaState()

    def _save(self, scope: str, state: BetaState):
        with self._connect() as conn:
            conn.execute(
                "UPDATE bayesian_threshold SET alpha=?,beta=?,sample_count=?,updated_at=? WHERE scope=?",
                (state.alpha, state.beta, state.sample_count, datetime.now(timezone.utc).isoformat(), scope),
            )
            conn.commit()

    def get_block_threshold(self, attack_class: Optional[str] = None) -> float:
        g = self._load("global").threshold
        if attack_class and attack_class in ATTACK_CLASSES:
            cs = self._load(attack_class)
            if cs.sample_count >= 10:
                return cs.threshold
        return g

    def get_class_thresholds(self) -> Dict[str, float]:
        g = self._load("global").threshold
        return {c: (self._load(c).threshold if self._load(c).sample_count >= 10 else g) for c in ATTACK_CLASSES}

    def process_feedback(self, event: Dict[str, Any]) -> Dict[str, Any]:
        global _last_update_result
        scan_id = event.get("scan_id", "")
        verdict = event.get("human_verdict", "")
        decision = event.get("original_decision", "")
        cls = event.get("attack_class", "other")
        if cls not in ATTACK_CLASSES:
            cls = "other"

        gs = self._load("global")
        cs = self._load(cls)
        prev = gs.threshold
        gs.apply_update(verdict, decision)
        cs.apply_update(verdict, decision)
        self._save("global", gs)
        self._save(cls, cs)

        new_t = gs.threshold
        _threshold_history.append(new_t)
        drift = len(_threshold_history) >= 2 and abs(new_t - list(_threshold_history)[0]) > DRIFT_DELTA
        lo, hi = _credible_interval(gs.alpha, gs.beta)

        result = {
            "updated_alpha": round(gs.alpha, 4),
            "updated_beta": round(gs.beta, 4),
            "new_threshold": new_t,
            "threshold_95_low": lo,
            "threshold_95_high": hi,
            "confidence": "low" if gs.sample_count < 20 else ("medium" if gs.sample_count <= 100 else "high"),
            "recommendation": "stable" if abs(new_t - prev) < 0.01 else ("raise_threshold" if new_t > prev else "lower_threshold"),
            "class_thresholds": self.get_class_thresholds(),
            "drift_alert": drift,
            "reasoning": f"Threshold {'raised' if new_t > prev else 'lowered'} to {new_t:.2f} from {verdict} feedback.",
        }
        _last_update_result = result
        return result

    def status(self) -> Dict[str, Any]:
        gs = self._load("global")
        lo, hi = _credible_interval(gs.alpha, gs.beta)
        return {
            "updated_alpha": round(gs.alpha, 4),
            "updated_beta": round(gs.beta, 4),
            "new_threshold": gs.threshold,
            "block_threshold": self.get_block_threshold(),
            "warn_threshold": WARN_THRESHOLD,
            "threshold_95_low": lo,
            "threshold_95_high": hi,
            "confidence": "low" if gs.sample_count < 20 else "medium",
            "class_thresholds": self.get_class_thresholds(),
            "drift_alert": len(_threshold_history) >= 2 and abs(_threshold_history[-1] - _threshold_history[0]) > DRIFT_DELTA,
            "last_update": _last_update_result,
            "threshold_floor": THRESHOLD_FLOOR,
            "threshold_ceiling": THRESHOLD_CEILING,
        }


_engine: Optional[BayesianThresholdEngine] = None


def get_bayesian_engine() -> BayesianThresholdEngine:
    global _engine
    if _engine is None:
        _engine = BayesianThresholdEngine()
    return _engine


def decision_label(score: float, attack_class: Optional[str] = None, block_threshold: Optional[float] = None) -> str:
    block = block_threshold if block_threshold is not None else get_bayesian_engine().get_block_threshold(attack_class)
    if score >= block:
        return "BLOCK"
    if score >= WARN_THRESHOLD:
        return "WARN"
    return "ALLOW"
