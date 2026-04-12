# NFLIP / CSIC — Agent context (Phases 1–4)

Condensed reference for AI assistants and developers. The product UI brand is **NFLIP Forensic Intelligence** (`csic_frontend`).

## Pipeline overview

| Phase | Role | Primary API / mount |
|-------|------|---------------------|
| **1** | Secure ingestion: JIT session, WebSocket chunks, Merkle, sandbox, WORM ledger | `POST /api/ingestion/*`, `WS /ws/secure-stream/{session_id}` |
| **2** | Universal Translator: lineage → deobf → DRAIN3 → NER → chronograph → staging → human commit → DuckDB `normalized_logs` | `/api/phase2/*` |
| **3** | Hot/cold gateway: Phase 2 webhook → Parquet cold + DuckDB hot, TTL janitor | Mounted at `/api/phase3` (optional deps) |
| **4** | Magic Query UI: NL→SQL (Next route) + **live** rows via backend | `GET /api/phase4/parsed-logs?audit_id=…`, Next `POST /api/magic-query/run` |

## Integration contracts

1. **Audit identity**  
   Phase 1 writes `latest_ingestion_audit` in `localStorage`. The app also keeps **`csic_active_audit_id`** (React context: `activeAuditId` / `setActiveAuditId` in `csic_frontend/lib/app-context.tsx`) so Phases 3–4 know which ledger UUID to use.

2. **Phase 2 → Phase 3**  
   On successful `commit_staging`, `app/phase2/node6_staging.py` POSTs to **`PHASE3_WEBHOOK_URL`** (default `http://127.0.0.1:8000/api/phase3/phase2_webhook`) with `Lineage = staging_id`, `Target_User = unknown`, `Notes = …`.

3. **Phase 2 → Phase 4**  
   Committed rows land in DuckDB table **`normalized_logs`** (same DB file as `app/db/duckdb.py`: `data/analytics.duckdb`).  
   **`GET /api/phase4/parsed-logs`** maps those rows to the Magic Query shape (`parsed_logs` columns).

4. **Phase 4 frontend**  
   `csic_frontend/app/api/magic-query/run/route.ts` passes **`audit_id`** from the client; when set, it fetches live rows from the FastAPI endpoint above, then applies the same lightweight filters as the demo dataset.

## Run commands

- Backend: `uvicorn app.main:new_app --host 0.0.0.0 --port 8000 --reload`
- Frontend: `cd csic_frontend && npm run dev`  
 Set `NEXT_PUBLIC_API_URL` to the backend base (e.g. `http://127.0.0.1:8000`) so server-side routes can reach Phase 4 API.

## Related docs

- Full Phase 1 security write-up: repository `README.md`.
