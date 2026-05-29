import os
from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    # App Settings
    app_name: str = "CodeSentinel AI Backend"
    app_env: str = "production"
    debug: bool = False
    
    # Security & API Integration
    anthropic_api_key: str = "mock-key"
    github_webhook_secret: Optional[str] = None
    github_token: Optional[str] = None
    
    # Redis Configurations
    redis_url: str = "redis://localhost:6379/0"
    
    # Vector Database storage paths
    vector_db_path: str = "./data/vector_index"
    model_output_dir: str = "./data/models"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

settings = Settings()
