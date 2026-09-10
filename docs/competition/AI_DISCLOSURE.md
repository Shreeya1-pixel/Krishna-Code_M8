# AI Disclosure — M8 (SCD 2026)

Mandatory disclosure under the case rules: material AI assistance is named below, including the tools and what they did. I am the sole author of this case. The core design and security decisions are mine. This is not a fully AI-generated entry.

---

## AI Tools Used

| Tool | Model | Role |
|------|-------|------|
| **Cursor** (AI coding assistant) | Claude Sonnet 4.6 | Primary code generation and architecture |
| **Claude** (Anthropic) | Claude Sonnet 4.6 | Codebase design, attack/defense logic, prompt engineering |

---

## What AI Did

### Architecture & Planning
- Designed the overall P1–P8 build plan and phase gates
- Planned the agent turn state machine (node/edge graph with sha256 checkpoint chaining)
- Designed the 3-tier injection classifier (keyword → TF-IDF → LLM judge)
- Designed the dual-graph policy broker (AuthGraph + PACT-style provenance)

### Code Generation
- Generated all Python backend files (FastAPI, SQLAlchemy, attack suite, oracles, defenses)
- Generated all React/TypeScript frontend files (pages, components, API client)
- Implemented the ML detection modules (`entropy.py`, `ngram_similarity.py`, `tier2_classifier.py`, `bayesian_threshold.py`, `drift_detector.py`, `multilingual.py`, `securec_language.py`) to my specification
- Generated Docker configuration (`docker-compose.yaml`, Dockerfiles)
- Generated all test files (pytest unit + end-to-end)

### Attack & Defense Content
- Designed the 28-attack static suite across 6 categories
- Wrote all attack payloads (direct, indirect, tool misuse, exfiltration, multilingual, obfuscated)
- Implemented the MAP→BREAK→FALSIFY adaptive engine with 8 mutation strategies
- Implemented the MockLLM exploitable/defended behavior
- Wrote all oracle checks and severity mappings

### Documentation
- Generated `README.md`, `AI_DISCLOSURE.md`, `.env.example`
- Wrote the 5-minute demo script
- Documented known limitations and residual risks

---

## What I Did

- **Research and threat modelling**: Studied real incidents (EchoLeak, CVE-2025-32711), current frameworks (OWASP GenAI Top 10 2026, MITRE ATLAS), and existing tools (Garak, PyRIT, promptfoo) to define what the harness must prove
- **Case design**: The before/after resistance test, the poisoned-invoice demonstration, treating document text as data rather than instructions, the multilingual (Arabic/Urdu/Arabizi) attack angle, and deterministic oracle scoring instead of an LLM judge
- **Architecture decisions**: Selected FastAPI, SQLite, Recharts, Tailwind, node/edge execution tracing, and the offline-by-default demo strategy
- **Review and testing**: Ran and verified all tests, identified an oracle false-positive bug (fixed), verified all acceptance gates and every reported number by re-running the suite

---

## Third-Party Libraries (Key)

| Library | Use |
|---------|-----|
| FastAPI | Backend REST + SSE API |
| SQLAlchemy | SQLite ORM |
| scikit-learn | TF-IDF + LogReg classifier (Tier 2) |
| ReportLab | PDF report generation |
| React + Vite | Frontend SPA |
| Recharts | Charts and gauges |
| Tailwind CSS | Styling |
| Lucide React | Icons |

All data in this application is **simulated/fictional** and labelled as DEMO data. No real employee, salary, or personal information is present.
