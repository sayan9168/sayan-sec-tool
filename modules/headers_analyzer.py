import requests
from typing import List, Dict, Tuple
from core.utils import print_status

class HeadersAnalyzer:
    def __init__(self, session: requests.Session):
        self.session = session
        self.required_headers = [
            ("Strict-Transport-Security", "HSTS is not enabled. Vulnerable to downgrade attacks."),
            ("Content-Security-Policy", "CSP is missing. Risk of XSS/Data Injection."),
            ("X-Content-Type-Options", "X-Content-Type-Options: nosniff is missing. MIME sniffing risk."),
            ("X-Frame-Options", "X-Frame-Options is missing. Clickjacking risk."),
            ("X-XSS-Protection", "X-XSS-Protection is missing. (Note: Deprecated in modern browsers, but good for legacy)."),
            ("Referrer-Policy", "Referrer-Policy is missing. Info leak via Referer header."),
            ("Permissions-Policy", "Permissions-Policy is missing. Browser feature control risk.")
        ]

    def analyze(self, url: str) -> List[Dict]:
        """Analyze security headers and return missing ones"""
        results = []
        try:
            resp = self.session.get(url, timeout=5)
            headers = {k.lower(): v for k, v in resp.headers.items()}
            
            score = 0
            total = len(self.required_headers)
            
            for header, risk_msg in self.required_headers:
                if header.lower() not in headers:
                    results.append({
                        "type": "Missing Security Header",
                        "header": header,
                        "risk": risk_msg,
                        "severity": "MEDIUM",
                        "remediation": f"Add '{header}' header to server configuration."
                    })
                else:
                    score += 1
            
            # Check for 'Server' header disclosure
            if 'server' in headers:
                results.append({
                    "type": "Information Disclosure",
                    "header": "Server",
                    "value": headers['server'],
                    "risk": "Server version disclosure may help attackers.",
                    "severity": "LOW",
                    "remediation": "Remove or obfuscate the Server header."
                })

            # Calculate Grade
            grade = "A+" if score == total else \
                    "A" if score >= total - 1 else \
                    "B" if score >= total - 3 else \
                    "C" if score >= total - 5 else "F"
            
            print_status(f"🔒 Security Headers Grade: {grade} ({score}/{total})", "INFO")
            return results
            
        except Exception as e:
            print_status(f"❌ Header Analysis failed: {e}", "ERROR")
            return []
