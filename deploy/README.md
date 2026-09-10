# Deploy

Same deploy configs also live at the **repo root** so `docker compose up` and Railway “Dockerfile in root” just work.

| File | Use |
|------|-----|
| `Dockerfile` | Single service: build React UI + serve via FastAPI |
| `docker-compose.yaml` | Local API + Vite frontend as two containers |
| `railway.json` | Railway healthcheck / builder hints |

## Build & run (single container)

From repo root:

```bash
docker build -f deploy/Dockerfile -t m8 .
docker run --rm -p 8000:8000 \
  -e LLM_PROVIDER=mock \
  -e SENTINEL_SEED_BASELINE=false \
  m8
```

Open http://localhost:8000

## Railway

1. New project → empty service  
2. Connect this GitHub repo **or** deploy with root `Dockerfile`  
3. Set env from `.env.example` (optional Slack/Jira)  
4. Set `SENTINEL_SEED_BASELINE=false`  
5. Generate a public domain  

Healthcheck path: `/health`
