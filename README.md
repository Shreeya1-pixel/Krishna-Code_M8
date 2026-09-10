# M8 — Adaptive Red-Team Testing for AI Agents

**SCD 2026** | School of Cyber Defense  
**Repo:** [Shreeya1-pixel/Krishna-Code_M8](https://github.com/Shreeya1-pixel/Krishna-Code_M8)

M8 is an offline AI-agent security testing harness. It attacks a small assistant (**SecureAssist**) with two tools, scores each attack deterministically, turns defenses on, and shows the ASR drop — with evidence, CI gate, and optional Slack/Jira alerts.

No OpenAI key required. Default mode is fully offline (`LLM_PROVIDER=mock`).

---

## Quick start (local)

### 1. Backend (terminal A)

```bash
cd Krishna-Code_M8   # or your clone folder
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r backend/requirements.txt
cp .env.example .env               # optional; empty = offline mock
PYTHONPATH=. python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

API health: http://127.0.0.1:8000/health

### 2. Frontend (terminal B)

```bash
cd frontend
npm install
npm run dev -- --host 127.0.0.1 --port 5173
```

UI: http://127.0.0.1:5173

### 3. One-command Docker (optional)

```bash
docker compose -f deploy/docker-compose.yaml up --build
# or from repo root (same compose file is copied):
docker compose up --build
```

- API: http://localhost:8000  
- UI (compose): http://localhost:5173  

Production-style single container (API serves the built UI):

```bash
docker build -f deploy/Dockerfile -t m8 .
docker run --rm -p 8000:8000 m8
# open http://localhost:8000
```

---

## Repository layout

```text
Krishna-Code_M8/
├── README.md                 ← you are here
├── .env.example              ← copy to .env for Slack/Jira/LLM overrides
├── Dockerfile                ← same as deploy/Dockerfile (root convenience)
├── docker-compose.yaml
├── railway.json
│
├── backend/                  ← FastAPI API + agent + attacks + defenses
│   ├── main.py               ← app entry (uvicorn backend.main:app)
│   ├── agent/                ← SecureAssist (MockLLM, tools, execution graph)
│   ├── attacks/              ← 28-attack suite + adaptive M8 mutations
│   ├── defenses/             ← classifier, policy broker, output guard, ML
│   ├── scoring/              ← deterministic oracles (SUCCEEDED/PARTIAL/BLOCKED)
│   ├── workflow/             ← CI gate, Slack, Jira, regression
│   ├── reports/              ← JSON/PDF report generation
│   ├── store/                ← SQLite persistence
│   ├── tests/                ← pytest
│   └── requirements.txt
│
├── frontend/                 ← React + Vite UI
│   └── src/pages/            ← Dashboard, Target Agent, Run Assessment, …
│
├── scripts/                  ← PDF / slide generators (offline)
├── submission/               ← competition PDF artifact(s)
│
├── docs/                     ← human docs (not required to run the app)
│   ├── demo/                 ← live demo script + oral defence notes
│   ├── competition/          ← AI disclosure, pitch, slide source
│   └── architecture/         ← Mermaid diagrams
│
└── deploy/                   ← Docker / Railway notes (mirrors root deploy files)
```

| Path | What it is |
|------|------------|
| `backend/` | Everything that runs the harness and API |
| `frontend/` | Browser UI |
| `docs/demo/` | What to say on stage |
| `docs/competition/` | SCD disclosure / pitch / slide text |
| `docs/architecture/` | System diagrams for Mermaid |
| `submission/` | Final PDF to upload for the case |
| `deploy/` | How to containerize / host |

---

## What to click in the UI

1. **Target Agent** — SecureAssist + `read_document` / `lookup_employee`  
2. **Run Assessment** — Vulnerable suite → then Defended suite  
3. **Defences** — multilingual checks + LoRA *plan* (not live training)  
4. **Workflow** — CI gate + Slack/Jira open links  
5. **Reports** — ASR, utility, residual gaps  

Full spoken script: [`docs/demo/DEMO_SCRIPT_M8.txt`](docs/demo/DEMO_SCRIPT_M8.txt)

---

## Tests

```bash
source .venv/bin/activate
PYTHONPATH=. pytest backend/tests -q
```

---

## Environment variables

Defaults work offline. Only set these if you want live integrations:

| Variable | Purpose |
|----------|---------|
| `LLM_PROVIDER` | `mock` (default) / `openai` / `anthropic` |
| `SLACK_WEBHOOK_URL` | Real Slack alerts |
| `SLACK_CHANNEL_URL` | Optional “Open Slack” deep link |
| `JIRA_BASE_URL` | e.g. `https://yourorg.atlassian.net` |
| `JIRA_USER_EMAIL` | Atlassian account email |
| `JIRA_API_TOKEN` | API token |
| `JIRA_PROJECT_KEY` | e.g. `KAN` |
| `SENTINEL_SEED_BASELINE` | `false` on cloud (faster boot) |

See [`.env.example`](.env.example). **Never commit `.env`.**

---

## Docs index

- Demo script → [`docs/demo/DEMO_SCRIPT_M8.txt`](docs/demo/DEMO_SCRIPT_M8.txt)  
- AI disclosure → [`docs/competition/AI_DISCLOSURE.md`](docs/competition/AI_DISCLOSURE.md)  
- Architecture Mermaid → [`docs/architecture/ARCHITECTURE_MERMAID.md`](docs/architecture/ARCHITECTURE_MERMAID.md)  
- Pitch → [`docs/competition/PITCH.md`](docs/competition/PITCH.md)  

---

## Honest scope

- Target LLM is a **deterministic MockLLM** so jury results replay.  
- Oracles are **string/behavior checks**, not LLM-as-judge.  
- LoRA feature generates a **retraining plan**; it does not fine-tune on stage.  
- All employee/SSN data is **simulated**.
