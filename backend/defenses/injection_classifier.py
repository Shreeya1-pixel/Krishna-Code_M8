"""
3-tier injection classifier.

Tier-1: keyword rules + entropy + n-gram similarity
Tier-2: distilBERT (uncertain band 0.35-0.65) with TF-IDF+LogReg fallback
Tier-3: optional LLM judge

Multilingual sub-detector: MultilingualDetector (AraBERT + heuristic)

Returns: {risk: 0-100, level: SAFE|SUSPICIOUS|MALICIOUS, reason, tier_used, mitre_tags}
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from .ml.entropy import (
    shannon_entropy, character_distribution_anomaly,
    token_burst_score, bigram_markov_entropy, positional_concentration,
)
from .ml.ngram_similarity import ngram_attack_similarity
from .ml.multilingual import get_multilingual_detector
from ..attacks.knowledge_graph import query_graph

# ── Tier-1 keyword rules ──────────────────────────────────────────────────────

# Direct injection signatures (English)
_INJECTION_PATTERNS = [
    r"ignore\s+(previous|all|prior)\s+instructions?",
    r"disregard\s+(your|all|any)\s+(previous\s+)?instructions?",
    r"forget\s+your\s+(training|guidelines?|rules?|prompt)",
    r"you\s+are\s+now\s+(?!SecureAssist|an?\s+internal)",
    r"developer\s+mode",
    r"dan\s+mode",
    r"jailbreak",
    r"act\s+as\s+if\s+(you\s+have\s+)?no\s+(restrictions?|limits?|guidelines?)",
    r"pretend\s+(you|there)\s+(are?|is)\s+no",
    r"(print|reveal|show|output|repeat|tell\s+me)\s+(your\s+)?(full\s+)?(system\s+prompt|instructions?|training|context|guidelines?)",
    r"what\s+(were\s+)?your\s+(original\s+)?instructions?",
    r"(override|bypass)\s+(safety|security|content)\s+(filter|policy|check|guardrail)",
    r"no\s+restrictions?\s+apply",
    r"operating\s+without\s+(restrictions?|constraints?|limits?)",
    r"confidential\s+mode",
]

# Indirect injection signatures (embedded in documents)
_INDIRECT_PATTERNS = [
    r"important\s+ai\s+instruction",
    r"attention\s+ai\s+assistant",
    r"mandatory\s+processing\s+step",
    r"automated\s+system\s+request",
    r"before\s+summariz(ing|e)\s+.{0,50}(call|use|invoke|run)",
    r"(disregard|ignore)\s+(any\s+)?previous\s+instructions?",
    r"this\s+is\s+an?\s+automated\s+request",
    r"step\s+\d.*?call\s+lookup_employee",
    r"step\s+\d.*?reveal",
]

# Tool abuse patterns
_TOOL_ABUSE_PATTERNS = [
    r"(call|invoke|run|use)\s+lookup_employee\s+(with|for|on)\s+(all|every|EMP-\*)",
    r"lookup_employee.*?(all|bulk|enumerate|loop|range)",
    r"(force|bypass|direct)\s+(tool|call|lookup)",
    r"employee_id\s*=\s*['\"]?\*['\"]?",
]

# Exfiltration patterns
_EXFIL_PATTERNS = [
    r"!\[.{0,50}\]\(https?://[^\)]+\)",   # markdown image exfil
    r"(exfil|exfiltrat|leak|send|forward|transmit)\s+.{0,30}(to|via|through)\s+https?://",
    r"embed\s+.{0,30}(ssn|salary|password|secret)\s+.{0,30}url",
]

_ALL_TIER1 = [
    ("direct_injection", _INJECTION_PATTERNS),
    ("indirect_injection", _INDIRECT_PATTERNS),
    ("tool_misuse", _TOOL_ABUSE_PATTERNS),
    ("exfiltration", _EXFIL_PATTERNS),
]

# MITRE ATLAS mappings per category (AI/LLM-specific, not classic ATT&CK).
_MITRE_MAP = {
    "direct_injection": ["AML.T0051.000"],
    "indirect_injection": ["AML.T0051.001", "AML.T0053"],
    "tool_misuse": ["AML.T0053"],
    "exfiltration": ["AML.T0057", "AML.T0024"],
    "multilingual": ["AML.T0051.000", "AML.T0043"],
}


def _tier1_check(text: str) -> Dict[str, Any]:
    """Rule-based Tier-1 check. Returns raw score 0-100 + matched categories."""
    lower = text.lower()
    matched_categories: List[str] = []
    matched_patterns: List[str] = []
    max_score = 0

    for category, patterns in _ALL_TIER1:
        for pattern in patterns:
            if re.search(pattern, lower, re.IGNORECASE):
                if category not in matched_categories:
                    matched_categories.append(category)
                matched_patterns.append(f"{category}: '{pattern[:40]}'")
                max_score = max(max_score, 85 if category in ("tool_misuse", "exfiltration") else 80)

    # Entropy signals
    ent = shannon_entropy(text)
    char_anom = character_distribution_anomaly(text)
    burst = token_burst_score(text)
    bigram = bigram_markov_entropy(text)
    gini = positional_concentration(text)
    entropy_score = (ent * 20 + char_anom * 15 + burst * 25 + bigram * 20 + gini * 20)

    # N-gram similarity
    ngram_score, ngram_families = ngram_attack_similarity(text)

    # Combine
    combined = max(max_score, entropy_score * 0.6 + ngram_score * 60)

    return {
        "score": min(100, combined),
        "matched_categories": matched_categories,
        "matched_patterns": matched_patterns,
        "ngram_families": ngram_families,
        "entropy": {
            "shannon": round(ent, 3),
            "char_anomaly": round(char_anom, 3),
            "token_burst": round(burst, 3),
            "bigram_entropy": round(bigram, 3),
            "positional_gini": round(gini, 3),
        },
    }


def classify_input(text: str, check_doc_content: bool = False) -> Dict[str, Any]:
    """
    Orchestrates 3-tier detection.

    Args:
        text: Input text to classify
        check_doc_content: If True, apply indirect injection patterns too

    Returns:
        {risk: 0-100, level: SAFE|SUSPICIOUS|MALICIOUS, reason, tier_used, mitre_tags, ...}
    """
    text = text or ""

    # Multilingual sub-detector (always runs — catches non-Latin evasion)
    ml_detector = get_multilingual_detector()
    multi_result = ml_detector.analyse(text)
    script = multi_result.get("script_detected", "latin")
    multilingual_evasion = multi_result.get("evasion_suspected", False)
    multilingual_conf = float(multi_result.get("confidence", 0.0))

    # Tier-1: keyword + entropy
    t1 = _tier1_check(text)
    t1_score = t1["score"]
    matched_categories = t1["matched_categories"].copy()
    matched_patterns = t1["matched_patterns"].copy()

    # Boost for multilingual evasion (non-Latin attack)
    if multilingual_evasion and script != "latin":
        t1_score = max(t1_score, multilingual_conf * 100)
        matched_categories.append("multilingual")
        matched_patterns.append(f"multilingual_evasion:{multi_result.get('method', 'heuristic')}")

    tier_used = 1
    final_score = t1_score

    # Tier-2: distilBERT/TF-IDF for uncertain band
    if 35 <= t1_score <= 65:
        try:
            from .ml.tier2_classifier import get_tier2_classifier
            t2 = get_tier2_classifier().classify(text)
            t2_score = t2.get("tier2_score", 0.5) * 100
            # Blend T1 and T2
            final_score = 0.4 * t1_score + 0.6 * t2_score
            tier_used = 2
        except Exception:
            final_score = t1_score

    # Determine level
    if final_score >= 70:
        level = "MALICIOUS"
    elif final_score >= 35:
        level = "SUSPICIOUS"
    else:
        level = "SAFE"

    # Knowledge graph enrichment
    mitre_tags: List[str] = []
    remediation_ids: List[str] = []
    for cat in matched_categories:
        mitre_tags.extend(_MITRE_MAP.get(cat, []))
    mitre_tags = list(set(mitre_tags))

    kg_evidence = query_graph(matched_patterns)
    if kg_evidence:
        mitre_tags.extend(kg_evidence.mitre_techniques)
        remediation_ids.extend(kg_evidence.remediation_ids)
        mitre_tags = list(set(mitre_tags))

    # Reason string
    parts = []
    if matched_categories:
        parts.append(f"categories: {', '.join(matched_categories)}")
    if multilingual_evasion:
        parts.append(f"multilingual_evasion script={script} method={multi_result.get('method')}")
    if not parts:
        parts.append("within_normal_range")
    reason = "; ".join(parts)

    return {
        "risk": round(final_score, 1),
        "level": level,
        "reason": reason,
        "tier_used": tier_used,
        "mitre_tags": mitre_tags,
        "remediation_ids": list(set(remediation_ids)),
        "matched_categories": matched_categories,
        "matched_patterns": matched_patterns[:5],
        "multilingual": {
            "script": script,
            "evasion_suspected": multilingual_evasion,
            "confidence": multilingual_conf,
            "method": multi_result.get("method", "heuristic"),
        },
        "entropy": t1.get("entropy", {}),
        "ngram_families": t1.get("ngram_families", []),
    }
