"""
Cross-Site Scripting (XSS) Detection Module
Educational Research Only
"""
import re
import html
from typing import List, Dict, Optional
from urllib.parse import urlparse, parse_qs, quote
import requests
from core.utils import logger, print_status, inject_payload, extract_params
from config import config

def _check_reflected_xss(url: str, session: requests.Session, param: str) -> Optional[Dict]:
    """Check for reflected XSS vulnerabilities"""
    for payload in config.XSS_PAYLOADS:
        encoded_payload = quote(payload, safe='')
        test_url = inject_payload(url, param, encoded_payload)
        
        try:
            resp = session.get(test_url, timeout=config.TIMEOUT)
            content = resp.text
            
            # Check if payload is reflected without proper encoding
            if payload in content or html.unescape(payload) in content:
                # Additional check: is it in a dangerous context?
                dangerous_contexts = [
                    rf'<script[^>]*>.*?{re.escape(payload)}',
                    rf'<img[^>]+onerror\s*=\s*["\']?{re.escape(payload)}',
                    rf'javascript:.*?{re.escape(payload)}',
                    rf'<svg[^>]+onload\s*=\s*["\']?{re.escape(payload)}'
                ]
                
                for ctx_pattern in dangerous_contexts:
                    if re.search(ctx_pattern, content, re.I):
                        return {
                            "type": "Reflected XSS",
                            "url": test_url,
                            "param": param,
                            "payload": payload,
                            "evidence": f"Payload reflected in dangerous context",
                            "severity": "HIGH",
                            "timestamp": time.time() if 'time' in globals() else 0
                        }
                        
        except:
            continue
    return None

def _check_dom_xss_indicators(url: str, session: requests.Session) -> List[Dict]:
    """Check for potential DOM-based XSS vectors"""    results = []
    dom_sources = [
        'document.write', 'innerHTML', 'outerHTML',
        'document.writeln', 'eval(', 'setTimeout(', 'setInterval(',
        'location.hash', 'location.search', 'document.URL'
    ]
    
    try:
        resp = session.get(url, timeout=config.TIMEOUT)
        content = resp.text
        
        for source in dom_sources:
            if source in content:
                results.append({
                    "type": "Potential DOM XSS Vector",
                    "url": url,
                    "param": "N/A (DOM-based)",
                    "payload": source,
                    "evidence": f"Found dangerous DOM sink: {source}",
                    "severity": "MEDIUM",
                    "timestamp": time.time() if 'time' in globals() else 0
                })
    except:
        pass
    
    return results

def _check_stored_xss_hints(url: str, session: requests.Session) -> Optional[Dict]:
    """Look for potential stored XSS entry points"""
    # Check for forms without CSRF tokens or input sanitization hints
    try:
        resp = session.get(url, timeout=config.TIMEOUT)
        content = resp.text.lower()
        
        # Look for forms with user input fields
        if '<form' in content and ('input' in content or 'textarea' in content):
            # Check for missing security indicators
            has_csrf = 'csrf' in content or 'token' in content or 'authenticity' in content
            has_sanitization = 'sanitize' in content or 'escape' in content or 'htmlspecialchars' in content
            
            if not has_csrf and not has_sanitization:
                return {
                    "type": "Potential Stored XSS Entry Point",
                    "url": url,
                    "param": "form_input",
                    "payload": "N/A",
                    "evidence": "Form found without apparent CSRF protection or sanitization",
                    "severity": "MEDIUM",
                    "timestamp": time.time() if 'time' in globals() else 0
                }    except:
        pass
    return None

def scan(url: str, session: requests.Session) -> List[Dict]:
    """Main scan function for XSS vulnerabilities"""
    results = []
    parsed = urlparse(url)
    
    # Check reflected XSS on parameters
    if parsed.query:
        params = extract_params(url)
        for param in params.keys():
            result = _check_reflected_xss(url, session, param)
            if result:
                results.append(result)
                print_status(f"⚠️ Found: {result['type']} in param '{param}'", "WARNING")
    
    # Check DOM-based indicators
    dom_results = _check_dom_xss_indicators(url, session)
    results.extend(dom_results)
    
    # Check for stored XSS potential
    stored_result = _check_stored_xss_hints(url, session)
    if stored_result:
        results.append(stored_result)
        print_status(f"⚠️ Found: {stored_result['type']}", "WARNING")
    
    return results

# Import time for timestamp
import time
