from pydantic_settings import BaseSettings
from typing import Optional

class Settings(BaseSettings):
    PROJECT_NAME: str = "AI SOC Analyst API"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"
    
    # LLM Settings
    LLM_API_KEY: Optional[str] = None
    LLM_MODEL: str = "gemini-1.5-flash"
    LLM_PROVIDER: str = "google" # google, openai, groq, openrouter
    
    # Detection Thresholds
    BRUTE_FORCE_FAILED_THRESHOLD: int = 5
    BRUTE_FORCE_WINDOW_SECONDS: int = 300
    
    PORT_SCAN_UNIQUE_PORTS_THRESHOLD: int = 15
    PORT_SCAN_WINDOW_SECONDS: int = 120
    
    DOS_EVENT_COUNT_THRESHOLD: int = 50
    DOS_WINDOW_SECONDS: int = 60
    
    PRIVILEGE_ANOMALY_SENSITIVE_USERS: list[str] = ["root", "admin", "administrator", "SYSTEM", "sudo"]
    
    # ML Detection Settings
    ML_CONTAMINATION: float = 0.15
    ML_RANDOM_STATE: int = 42

    class Config:
        env_file = ".env"
        case_sensitive = True

settings = Settings()
