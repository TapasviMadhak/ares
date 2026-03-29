"""
Configuration management for ARES
"""

import os
from pathlib import Path
from typing import Optional
from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    """Application settings"""
    
    # Application
    ares_env: str = Field(default="development", alias="ARES_ENV")
    ares_debug: bool = Field(default=True, alias="ARES_DEBUG")
    ares_host: str = Field(default="0.0.0.0", alias="ARES_HOST")
    ares_port: int = Field(default=8000, alias="ARES_PORT")
    
    # Database
    database_url: str = Field(alias="DATABASE_URL")
    db_echo: bool = Field(default=False, alias="DB_ECHO")
    
    # Redis
    redis_url: str = Field(default="redis://localhost:6379/0", alias="REDIS_URL")
    
    # Ollama
    ollama_host: str = Field(default="http://localhost:11434", alias="OLLAMA_HOST")
    ollama_model: str = Field(default="llama3.2:8b", alias="OLLAMA_MODEL")
    
    # Burp Suite
    burp_api_url: str = Field(default="http://localhost:1337", alias="BURP_API_URL")
    burp_api_key: Optional[str] = Field(default=None, alias="BURP_API_KEY")
    
    # MCP Server
    mcp_host: str = Field(default="localhost", alias="MCP_HOST")
    mcp_port: int = Field(default=8001, alias="MCP_PORT")
    
    # Security
    secret_key: str = Field(alias="SECRET_KEY")
    allowed_origins: list[str] = Field(
        default=["http://localhost:3000", "http://localhost:5173"],
        alias="ALLOWED_ORIGINS"
    )
    
    # Logging
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")
    log_file: str = Field(default="/mnt/d_drive/ares/logs/ares.log", alias="LOG_FILE")
    
    # Scanning
    max_concurrent_scans: int = Field(default=5, alias="MAX_CONCURRENT_SCANS")
    scan_timeout: int = Field(default=3600, alias="SCAN_TIMEOUT")
    rate_limit: int = Field(default=100, alias="RATE_LIMIT")
    
    # Model Training
    training_data_dir: Path = Field(
        default=Path("/mnt/d_drive/ares/data/training"),
        alias="TRAINING_DATA_DIR"
    )
    model_output_dir: Path = Field(
        default=Path("/mnt/d_drive/ares/models"),
        alias="MODEL_OUTPUT_DIR"
    )
    
    # Storage
    scan_results_dir: Path = Field(
        default=Path("/mnt/d_drive/ares/data/scan_results"),
        alias="SCAN_RESULTS_DIR"
    )
    reports_dir: Path = Field(
        default=Path("/mnt/d_drive/ares/data/reports"),
        alias="REPORTS_DIR"
    )
    
    class Config:
        env_file = str(Path(__file__).parent.parent / ".env")
        env_file_encoding = "utf-8"
        case_sensitive = False
        extra = "ignore"


# Global settings instance
settings = Settings()
