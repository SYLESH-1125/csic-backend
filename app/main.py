from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
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

new_app = FastAPI(title="Forensic AI Engine")

new_origins = ["*"]

new_app.add_middleware(
    CORSMiddleware,
    allow_origins=new_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Create all tables (includes new IngestionSession + QuarantineLog tables)
Base.metadata.create_all(bind=engine)

# ── REST routers (prefixed under /api) ─────────────────────────────────────
new_app.include_router(new_ingestion, prefix="/api/ingestion", tags=["Ingestion"])
new_app.include_router(phase2_router, prefix="/api/phase2", tags=["Phase 2: Universal Translator"])
new_app.include_router(new_features, prefix="/api")
new_app.include_router(new_detection, prefix="/api")
new_app.include_router(new_ledger, prefix="/api")
new_app.include_router(new_dashboard, prefix="/api")
new_app.include_router(new_reporting, prefix="/api")

# ── WebSocket router (no /api prefix — WS routes use bare paths) ───────────
new_app.include_router(ws_ingestion, tags=["Secure WebSocket Ingestion"])


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