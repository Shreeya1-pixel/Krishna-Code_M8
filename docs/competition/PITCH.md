# M8 — Pitch (jury + business)

## The one line
**M8: Adaptive Red-Team Testing for AI Agents.** Break the agent, mutate the attack, and prove the defense before it touches production or government systems.

## The problem (why now)
Governments and enterprises are wiring LLM agents into real workflows — reading email, calling tools, touching internal data. That turns prompt injection from theory into a live attack surface, and most teams ship with **no security test at all**.

This is not hypothetical:
- **EchoLeak (CVE-2025-32711, CVSS 9.3, 2025):** a single crafted email made Microsoft 365 Copilot exfiltrate internal data with **zero clicks**, bypassing its own injection classifier via a markdown-image URL. First real-world weaponized indirect prompt injection.
- **OWASP Top 10 for Agentic Applications (2026)** now ranks unsafe tool invocation and untrusted external content as top risks.

If it happened to Microsoft, it will happen to a ministry AI assistant.

## The gap in today's tools
Garak, PyRIT, promptfoo, and Lakera are good at probing **prompts**. Independent 2026 comparisons rate all of them **weak** at the two things that actually cause breaches:
- **application-level authorization review**, and
- **unsafe tool-use / boundary validation**.

They tell you a prompt is risky. They don't prove your agent's **tools and permissions** are safe, and they don't hand you a **before/after proof** that a fix worked.

## Why it's technically credible (not a hackathon toy)
- **State-of-the-art defense, not an allow-list.** The policy broker uses dual-graph authorization-vs-provenance and argument-level trust contracts — the 2026 research approach (AuthGraph, PACT) that cuts indirect-injection success from ~40% to ~1% without killing task utility.
- **Real ML detector,** ported from a prior production system: a 3-tier cascade (heuristics/entropy → distilBERT with CPU fallback → LLM guard), n-gram similarity, an adaptive Bayesian block-threshold that learns from feedback, PSI drift detection, and a LoRA retraining-plan generator for a future self-improving guardrail.
- **Research-grade metrics:** we report Attack Success Rate *and* Utility together (the AgentDojo/InjecAgent security-utility tradeoff), so our before/after is comparable to named systems, not a bare percentage.
- **Region-relevant:** Arabic/Arabizi/mixed-script injection detection, which English-only tools miss.

## What M8 does differently
1. **Tool-authorization proof, not just prompt probing.** A real policy broker sits between the model and its tools; the model can't call a sensitive tool directly. We *measure* that this stops attacks prompt-only scanners miss.
2. **Pentest-until-broken engine.** An adaptive attacker escalates — rephrase, obfuscate, translate (incl. Arabic), embed in a document, split across turns — until it finds a working exploit, then a falsifier confirms it's real. Modeled on a real vuln-research loop (MAP → TRACE → BREAK → FALSIFY → REPORT).
3. **Before/after evidence report**, mapped to OWASP risks, with **honest residual gaps**. That's what a CISO signs off on.

## The demo (what the jury sees)
A helpful company assistant reads a document and answers questions. A normal-looking invoice quietly tells it to leak employee records. Defenses **off**: it obeys and emits an exfil URL — on screen. Defenses **on**, same attack: the broker blocks the tool call, the output guard strips the exfil, and the score drops from ~64% attack success to ~15%. Then we honestly show the Arabic/obfuscated variant that *still* slips through. Export a PDF report with remediation.

## Business
- **Buyer:** CISO / AI platform / GRC teams standing up agentic AI.
- **Wedge:** a CI security gate for agents — block the release if attack-success regresses, like a unit test for safety.
- **Workflow, not just a scan:** drops into CI/CD as a release gate — a critical exploit fails the build, opens a Jira ticket, and pings Slack before the agent ships. Regression tracking shows new exploits vs the last baseline.
- **Expansion:** scheduled re-tests (regression), MCP/tool-boundary coverage, compliance-mapped reports (OWASP, UAE PDPL-aligned handling), managed red-team service.
- **Why us / why here:** UAE is pushing AI into government fast (UAE PASS, digital services); a locally-built, Arabic-aware agent security gate is directly relevant to DESC's mission.

## Why it scores on the SCD rubric
- **Fit to brief / business problem (20%):** exact match — agent security testing for AI/gov infrastructure.
- **Relevance (15%):** solves the real, current failure mode (EchoLeak-class).
- **Prototype works (25%):** genuinely runnable, real attacks/defenses, offline demo mode so it never fails on stage.
- **Technical depth (25%):** policy broker + provenance + adaptive loop + deterministic oracles + node-graph tracing.
- **Innovation (15%):** authorization-level testing + before/after proof + multilingual/adaptive attacks — the gap the market leaders don't cover.
