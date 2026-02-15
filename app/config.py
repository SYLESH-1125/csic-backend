from pydantic_settings import BaseSettings
from pathlib import Path

class Settings(BaseSettings):
    APP_NAME: str = "Forensic AI Engine"
    DEBUG: bool = True
    DATABASE_URL: str = "sqlite:///data/ledger.db"
    SQLITE_DB_PATH: str = "data/ledger.db"
    RAW_STORAGE_PATH: str = "data/raw"
    PARQUET_STORAGE_PATH: str = "data/parquet"

    class Config:
        env_file = ".env"

settings = Settings()

Path(settings.RAW_STORAGE_PATH).mkdir(parents=True, exist_ok=True)
Path(settings.PARQUET_STORAGE_PATH).mkdir(parents=True, exist_ok=True)
