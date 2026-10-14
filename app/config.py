import os
from pydantic import BaseModel, Field
from typing import Optional, List
from dotenv import load_dotenv

load_dotenv()

class Settings(BaseModel):
    # Gateway settings
    HOST: str = os.getenv("GATEWAY_HOST", "0.0.0.0")
    PORT: int = int(os.getenv("GATEWAY_PORT", "8000"))
    DEBUG: bool = os.getenv("GATEWAY_DEBUG", "false").lower() == "true"
    
    # Database
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./security_gateway.db")
    SQLITE_DB_PATH: str = os.getenv("SQLITE_DB_PATH", "./security_gateway.db")
    
    # Real Provider API Keys (Stored server-side only)
    OPENAI_API_KEY: Optional[str] = os.getenv("OPENAI_API_KEY", None)
    OPENAI_BASE_URL: str = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
    ANTHROPIC_API_KEY: Optional[str] = os.getenv("ANTHROPIC_API_KEY", None)
    ANTHROPIC_BASE_URL: str = os.getenv("ANTHROPIC_BASE_URL", "https://api.anthropic.com/v1")
    
    # Mock Provider for testing/offline mode
    ENABLE_MOCK_UPSTREAM: bool = os.getenv("ENABLE_MOCK_UPSTREAM", "true").lower() == "true"
    
    # Policy and tools file paths
    POLICY_FILE_PATH: str = os.getenv("POLICY_FILE_PATH", "config/policies.yaml")
    TOOLS_FILE_PATH: str = os.getenv("TOOLS_FILE_PATH", "config/tools.yaml")
    
    # Rate Limiting Defaults
    DEFAULT_RPM: int = int(os.getenv("DEFAULT_RPM", "60"))
    DEFAULT_TPM: int = int(os.getenv("DEFAULT_TPM", "100000"))
    
    # System Prompt Canaries / Canary Token to detect prompt leaks
    CANARY_TOKENS: List[str] = ["SEC_CANARY_X9872", "CONFIDENTIAL_SYSTEM_INTERNAL"]

settings = Settings()
