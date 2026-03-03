from pydantic import field_validator
from pydantic_settings import BaseSettings
from pathlib import Path


class Settings(BaseSettings):
    APP_NAME: str = "Forensic AI Engine"
    DEBUG: bool = True
    DATABASE_URL: str = "sqlite:///data/ledger.db"
    SQLITE_DB_PATH: str = "data/ledger.db"
    RAW_STORAGE_PATH: str = "data/raw"
    PARQUET_STORAGE_PATH: str = "data/parquet"

    # Phase-1 secure ingestion paths
    WORM_STORAGE_PATH: str = "data/worm"
    QUARANTINE_PATH: str = "data/quarantine"
    TEMP_CHUNKS_PATH: str = "data/temp"

    # JIT session TTL (minutes)
    SESSION_TTL_MINUTES: int = 30

    @field_validator("DEBUG", mode="before")
    @classmethod
    def coerce_debug(cls, v: object) -> bool:
        """
        Accept string env-var values for DEBUG.
        Non-boolean strings like 'release'/'production'/'prod'/'false'/'0'
        are treated as False; everything else as True.
        """
        if isinstance(v, bool):
            return v
        if isinstance(v, str):
            return v.lower() not in {"false", "0", "no", "off", "release", "production", "prod"}
        return bool(v)

    class Config:
        env_file = ".env"


settings = Settings()

# Ensure all required directories exist at startup
for _path in (
    settings.RAW_STORAGE_PATH,
    settings.PARQUET_STORAGE_PATH,
    settings.WORM_STORAGE_PATH,
    settings.QUARANTINE_PATH,
    settings.TEMP_CHUNKS_PATH,
):
    Path(_path).mkdir(parents=True, exist_ok=True)
