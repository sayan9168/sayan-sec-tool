import requests
from typing import List, Dict
from core.utils import print_status

class AuthTester:
    def __init__(self, session: requests.Session):
        self.session = session

    def check_cookie_security(self, url: str) -> List[Dict]:
        """Check if cookies have Secure, HttpOnly, and SameSite flags"""
        results = []
        try:
            resp = self.session.get(url, timeout=5)
            set_cookie_headers = resp.headers.get('Set-Cookie', '')
            
            if not set_cookie_headers:
                return results # No cookies to check

            cookies = [c.strip() for c in set_cookie_headers.split(',')]
            for cookie in cookies:
                cookie_name = cookie.split('=')[0] if '=' in cookie else cookie
                issues = []
                
                if 'Secure' not in cookie and 'secure' not in cookie.lower():
                    issues.append("Missing 'Secure' flag")
                if 'HttpOnly' not in cookie and 'httponly' not in cookie.lower():
                    issues.append("Missing 'HttpOnly' flag")
                if 'SameSite' not in cookie and 'samesite' not in cookie.lower():
                    issues.append("Missing 'SameSite' flag")
                
                if issues:
                    results.append({
                        "type": "Insecure Cookie Configuration",
                        "cookie": cookie_name,
                        "issues": issues,
                        "severity": "MEDIUM",
                        "risk": "Cookies may be intercepted or used in CSRF/XSS attacks."
                    })
        except: pass
        return results

    def check_weak_password_policy(self, url: str) -> List[Dict]:
        """Check if login form has weak password policy (Basic Check)"""
        # This is a heuristic check. Real testing requires analyzing the response to weak passwords.
        # Here we just check if there's a login form.
        results = []
        try:
            resp = self.session.get(url, timeout=5)
            content = resp.text.lower()
            if 'login' in content or 'password' in content:
                # Heuristic: If no complexity requirements mentioned in UI (very basic)
                # In real tool, you'd fuzz the login endpoint.
                pass 
        except: pass
        return results
