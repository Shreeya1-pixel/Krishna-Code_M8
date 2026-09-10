"""PSI drift detector for M8."""
from __future__ import annotations

import logging
import math
from collections import deque
from datetime import datetime, timezone
from typing import Any, Deque, Dict, List, Optional

logger = logging.getLogger("sentinel.drift")

_SCRIPT_MAP = {"latin": 0, "arabic": 1, "urdu": 2, "arabizi": 3, "mixed": 4}
_CATEGORY_MAP = {
    "direct_injection": 0, "indirect_injection": 1, "tool_misuse": 2,
    "exfiltration": 3, "multilingual": 4, "other": 5,
}

WINDOW_SIZE = 500
BASELINE_SIZE = 200
PSI_THRESHOLD = 0.2


def _psi_1d(baseline: List[float], current: List[float], n_bins: int = 10) -> float:
    if not baseline or not current:
        return 0.0
    lo = min(min(baseline), min(current))
    hi = max(max(baseline), max(current))
    if hi == lo:
        return 0.0

    def _hist(vals):
        counts = [0] * n_bins
        for v in vals:
            idx = min(int((v - lo) / (hi - lo) * n_bins), n_bins - 1)
            counts[idx] += 1
        n = len(vals)
        return [max(c / n, 1e-6) for c in counts]

    bh = _hist(baseline)
    ch = _hist(current)
    return abs(sum((ch[i] - bh[i]) * math.log(ch[i] / bh[i]) for i in range(n_bins)))


class DriftDetector:
    def __init__(self):
        self._window: Deque[List[float]] = deque(maxlen=WINDOW_SIZE)
        self._baseline: List[List[float]] = []
        self._alerts: Deque[Dict[str, Any]] = deque(maxlen=50)
        self._baseline_locked = False

    def update(self, features: List[float]):
        self._window.append(features)
        if not self._baseline_locked and len(self._window) >= BASELINE_SIZE:
            self._baseline = list(self._window)
            self._baseline_locked = True
        if self._baseline_locked and len(self._window) % 50 == 0:
            self._check_drift()

    def _check_drift(self):
        if not self._baseline:
            return
        n_feat = len(self._baseline[0])
        names = ["script_type", "entropy", "attack_category", "length_bucket", "risk_score"]
        psi_scores: Dict[str, float] = {}
        drift = False
        for i in range(n_feat):
            base_col = [row[i] for row in self._baseline]
            curr_col = [row[i] for row in self._window]
            psi = _psi_1d(base_col, curr_col)
            label = names[i] if i < len(names) else f"feat_{i}"
            psi_scores[label] = round(psi, 4)
            if psi > PSI_THRESHOLD:
                drift = True
        if drift:
            self._alerts.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "psi_scores": psi_scores,
            })
            logger.warning("DriftDetector DRIFT psi=%s", psi_scores)

    def status(self) -> Dict[str, Any]:
        if not self._baseline or not self._window:
            return {"drift_detected": False, "psi_scores": {}, "alert_count": 0,
                    "last_alert": None, "baseline_size": len(self._baseline)}
        n_feat = len(self._baseline[0])
        names = ["script_type", "entropy", "attack_category", "length_bucket", "risk_score"]
        psi_scores: Dict[str, float] = {}
        drift = False
        for i in range(n_feat):
            base_col = [row[i] for row in self._baseline]
            curr_col = [row[i] for row in self._window]
            psi = _psi_1d(base_col, curr_col)
            label = names[i] if i < len(names) else f"feat_{i}"
            psi_scores[label] = round(psi, 4)
            if psi > PSI_THRESHOLD:
                drift = True
        return {
            "drift_detected": drift,
            "psi_scores": psi_scores,
            "alert_count": len(self._alerts),
            "last_alert": self._alerts[-1]["timestamp"] if self._alerts else None,
            "baseline_size": len(self._baseline),
        }


def make_feature_vector(
    script: str, entropy: float, attack_categories: List[str],
    payload_len: int, risk_score: float,
) -> List[float]:
    script_enc = float(_SCRIPT_MAP.get(script, 0))
    cat_enc = float(_CATEGORY_MAP.get(attack_categories[0] if attack_categories else "other", 5))
    lb = (0 if payload_len < 20 else 1 if payload_len < 50 else 2 if payload_len < 100 else
          3 if payload_len < 200 else 4 if payload_len < 500 else 5)
    return [script_enc, float(entropy), cat_enc, float(lb), float(risk_score)]


_detector = DriftDetector()


def get_drift_detector() -> DriftDetector:
    return _detector
