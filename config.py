import os
from dotenv import load_dotenv
from typing import Optional

load_dotenv()

class Config:
    # API Keys
    VT_API_KEY: Optional[str] = os.getenv("VT_API_KEY")
    VIRUSTOTAL_API_KEY: Optional[str] = os.getenv("VIRUSTOTAL_API_KEY") or os.getenv("VT_API_KEY")
    PHISHTANK_API_KEY: Optional[str] = os.getenv("PHISHTANK_API_KEY")
    
    # Timeouts & Limits
    HTTP_TIMEOUT: float = float(os.getenv("HTTP_TIMEOUT", "10.0"))
    MAX_URLS_PER_REQUEST: int = int(os.getenv("MAX_URLS_PER_REQUEST", "10"))
    
    # Security thresholds
    ENTROPY_THRESHOLD: float = float(os.getenv("ENTROPY_THRESHOLD", "4.5"))
    MAX_PATH_LENGTH: int = int(os.getenv("MAX_PATH_LENGTH", "100"))
    
    # Rate limiting
    RATE_LIMIT_PER_MINUTE: int = int(os.getenv("RATE_LIMIT_PER_MINUTE", "60"))
    
    @classmethod
    def validate(cls) -> bool:
        """Validate critical configuration"""
        if not cls.VT_API_KEY and not cls.VIRUSTOTAL_API_KEY:
            print("WARNING: No VirusTotal API key found. Some features will be limited.")
            return False
        return True

config = Config()
