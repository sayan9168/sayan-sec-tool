"""
MITM Proxy Module - HTTP/S Traffic Interceptor
Educational Purpose Only
"""
from mitmproxy import http, ctx
from datetime import datetime
import json
import re
from .utils import logger, print_status

class SecurityInterceptor:
    """Intercept and analyze HTTP/S traffic"""
    
    def __init__(self):
        self.request_log = []
        self.sensitive_patterns = [
            r'password[\s]*[:=]',
            r'api[_-]?key[\s]*[:=]',
            r'token[\s]*[:=]',
            r'session[_-]?id[\s]*[:=]',
            r'credit[_-]?card',
            r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b'  # CC pattern
        ]
    
    def request(self, flow: http.HTTPFlow):
        """Intercept and log outgoing requests"""
        req_info = {
            "timestamp": datetime.now().isoformat(),
            "method": flow.request.method,
            "url": flow.request.url,
            "headers": dict(flow.request.headers),
            "body": flow.request.text[:500] if flow.request.text else None
        }
        self.request_log.append(req_info)
        
        # Log to console
        print_status(f"{flow.request.method} {flow.request.url}", "INFO")
        
        # Check for sensitive data in request
        self._check_sensitive_data(flow.request, "REQUEST")
    
    def response(self, flow: http.HTTPFlow):
        """Intercept and analyze responses"""
        print_status(f"Response: {flow.response.status_code} - {flow.request.url}", "INFO")
        
        # Check for sensitive data leakage
        self._check_sensitive_data(flow.response, "RESPONSE")
        
        # Check security headers
        self._check_security_headers(flow.response)
    
    def _check_sensitive_data(self, obj, direction: str):
        """Check for sensitive information leakage"""
        content = obj.text if hasattr(obj, 'text') else ""
        if not content:
            return
            
        for pattern in self.sensitive_patterns:
            if re.search(pattern, content, re.I):
                print_status(
                    f"⚠️ Potential sensitive data leak in {direction}: {pattern}",
                    "WARNING"
                )
                logger.warning(f"Sensitive pattern '{pattern}' found in {direction}")
    
    def _check_security_headers(self, response: http.Response):
        """Check for missing security headers"""
        required_headers = [
            'X-Content-Type-Options',
            'X-Frame-Options', 
            'X-XSS-Protection',
            'Strict-Transport-Security',
            'Content-Security-Policy'
        ]
        
        for header in required_headers:
            if header not in response.headers:
                print_status(f"🔍 Missing security header: {header}", "WARNING")

    def done(self, flow: http.HTTPFlow):
        """Log completed flow"""
        pass

# mitmproxy addon instance
addons = [SecurityInterceptor()]

def start_proxy(host: str = "127.0.0.1", port: int = 8080):
    """Start proxy server (called from main)"""
    print_status(f"🔌 Starting proxy on {host}:{port}", "INFO")
    print_status("Configure your browser to use this proxy", "INFO")
    print_status("Press Ctrl+C to stop", "WARNING")
    # Note: Actual proxy startup handled by mitmproxy CLI
