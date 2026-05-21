import os
import sys
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pathlib import Path
from app.core.logging import logger
from app.db.base import Base
from app.db.session import engine, SessionLocal
from app.ingestion.integrity import verify_hash_chain
from app.ingestion.router import router as new_ingestion
from app.ingestion.ws_router import router as ws_ingestion
from app.features.router import router as new_features
from app.detection.router import router as new_detection
from app.ledger.router import router as new_ledger
from app.dashboard.router import router as new_dashboard
from app.reporting.router import router as new_reporting
from app.phase2.router import router as phase2_router
from app.phase4.router import router as phase4_router
from app.auth.router import router as auth_router
from fastapi.responses import JSONResponse

new_app = FastAPI(title="Forensic AI Engine")

new_origins = ["*"]

new_app.add_middleware(
    CORSMiddleware,
    allow_origins=new_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Create tables locally; skip on Vercel (read-only/ephemeral filesystem).
if not os.environ.get("VERCEL"):
    Base.metadata.create_all(bind=engine)

# ── REST routers (prefixed under /api) ─────────────────────────────────────
new_app.include_router(auth_router, prefix="/api/auth", tags=["Authentication"])
new_app.include_router(new_ingestion, prefix="/api/ingestion", tags=["Ingestion"])
new_app.include_router(phase2_router, prefix="/api/phase2", tags=["Phase 2: Universal Translator"])
new_app.include_router(phase4_router, prefix="/api/phase4", tags=["Phase 4: Analytics Dataset"])
new_app.include_router(new_features, prefix="/api")
new_app.include_router(new_detection, prefix="/api")
new_app.include_router(new_ledger, prefix="/api")
new_app.include_router(new_dashboard, prefix="/api")
new_app.include_router(new_reporting, prefix="/api")

# ── Phase 5: NFLIP Operation Room (full FastAPI app — reporting + agents + Studio API) ──
_phase5_backend_root = Path(__file__).resolve().parent / "phase_5_CISC" / "operation-room" / "backend"
if _phase5_backend_root.is_dir():
    _p5 = str(_phase5_backend_root)
    if _p5 not in sys.path:
        sys.path.insert(0, _p5)
    try:
        from operation_room.main import app as phase5_operation_room_app

        new_app.mount("/api/phase5", phase5_operation_room_app)
        logger.info("Phase 5 Operation Room mounted at /api/phase5")
    except Exception as _p5_exc:
        logger.warning(
            "Phase 5 Operation Room not mounted: {} — install: pip install -r app/phase_5_CISC/operation-room/backend/requirements.txt",
            _p5_exc,
        )

# ── WebSocket router (no /api prefix — WS routes use bare paths) ───────────
new_app.include_router(ws_ingestion, tags=["Secure WebSocket Ingestion"])

# ── Phase 3 prototype app (mounted under /api/phase3) ──────────────────────
# This phase depends on optional heavyweight libs; mount only if available.
try:
    from app.phase3.phase3_hot_and_cold_db.main import new_app as phase3_app  # type: ignore
    new_app.mount("/api/phase3", phase3_app)
except Exception as _phase3_exc:
    @new_app.get("/api/phase3", include_in_schema=False)
    def _phase3_unavailable():
        return JSONResponse(
            status_code=503,
            content={
                "status": "unavailable",
                "detail": "Phase 3 app could not be mounted (missing optional dependencies).",
            },
        )


@new_app.get("/")
def health():
    return {"status": "Forensic Engine Online"}


@new_app.on_event("startup")
def startup_integrity_check():
    new_db = SessionLocal()
    try:
        new_result = verify_hash_chain(new_db)
        if hasattr(new_result, "get") and new_result.get("status") != "chain_valid":
            # Warning instead of error - common in development with existing data
            logger.warning(
                f"Hash chain integrity check: {new_result.get('status', 'unknown')} "
                f"(broken_at: {new_result.get('broken_at', 'N/A')})"
            )
            logger.info("Server continues - hash chain warnings are non-fatal in development")
        else:
            logger.info("Hash chain verified.")
    except Exception as new_e:
        logger.warning(f"Integrity check skipped: {new_e}")
    finally:
        new_db.close()

# Vercel FastAPI detection expects a top-level `app` (uvicorn still uses app.main:new_app).
app = new_app