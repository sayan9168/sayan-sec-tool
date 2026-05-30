import requests
from urllib.parse import urlparse, urljoin
from typing import List, Dict
from core.utils import print_status, logger

class APIScanner:
    def __init__(self, session: requests.Session):
        self.session = session

    def check_cors(self, url: str) -> List[Dict]:
        """Check for Misconfigured CORS (Wildcard Origin)"""
        results = []
        # Simulate a cross-origin request
        headers = {'Origin': 'https://evil.com'}
        try:
            resp = self.session.options(url, headers=headers, timeout=5)
            
            allow_origin = resp.headers.get('Access-Control-Allow-Origin', '')
            allow_creds = resp.headers.get('Access-Control-Allow-Credentials', '').lower()
            
            if allow_origin == '*' and allow_creds == 'true':
                results.append({
                    "type": "CORS Misconfiguration",
                    "url": url,
                    "evidence": "Access-Control-Allow-Origin: * with Credentials: true",
                    "severity": "HIGH",
                    "risk": "Allows attackers to steal authenticated data via cross-site requests."
                })
            elif allow_origin == 'https://evil.com':
                results.append({
                    "type": "CORS Misconfiguration",
                    "url": url,
                    "evidence": "Access-Control-Allow-Origin reflects arbitrary origin",
                    "severity": "HIGH",
                    "risk": "Server reflects Origin header without validation."
                })
        except: pass
        return results

    def check_exposed_docs(self, url: str) -> List[Dict]:
        """Check for exposed API documentation (Swagger/Redoc)"""
        results = []
        base_url = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
        docs_paths = [
            "/swagger.json", "/swagger-ui.html", "/api-docs", 
            "/v1/api-docs", "/openapi.json", "/graphiql", "/graphql"
        ]
        
        for path in docs_paths:
            try:
                resp = self.session.get(urljoin(base_url, path), timeout=5)
                if resp.status_code == 200 and ("swagger" in resp.text.lower() or "openapi" in resp.text.lower()):
                    results.append({
                        "type": "Exposed API Documentation",
                        "url": urljoin(base_url, path),
                        "evidence": f"Accessible API documentation at {path}",
                        "severity": "MEDIUM",
                        "risk": "Reveals API structure to attackers."
                    })
            except: continue
        return results

    def scan(self, url: str) -> List[Dict]:
        """Run all API checks"""
        findings = []
        print_status(f"🔌 Scanning API Security: {url[:50]}...", "INFO")
        
        findings.extend(self.check_cors(url))
        findings.extend(self.check_exposed_docs(url))
        
        return findings
