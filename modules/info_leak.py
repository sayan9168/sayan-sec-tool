"""
Sensitive Information Leakage Detection Module
Educational Research Only
"""
import re
from typing import List, Dict
import requests
from core.utils import logger, print_status
from config import config

# Patterns for sensitive data detection
SENSITIVE_PATTERNS = {
    "API Keys": [
        r'api[_-]?key\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})',
        r'apikey\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{16,})',
    ],
    "AWS Credentials": [
        r'(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}',  # AWS Access Key ID
        r'aws[_-]?secret\s*[:=]\s*["\']?([a-zA-Z0-9/+=]{40})',
    ],
    "Private Keys": [
        r'-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----',
        r'-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----',
    ],
    "JWT Tokens": [
        r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*',
    ],
    "Database URLs": [
        r'(mysql|postgresql|mongodb|redis):\/\/[^\s"\']+',
    ],
    "Email Addresses": [
        r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
    ],
    "Phone Numbers": [
        r'\+?[\d\s\-\(\)]{10,}',
    ],
    "Credit Card Patterns": [
        r'\b(?:\d{4}[\s-]?){3}\d{4}\b',
        r'\b3[47][0-9]{13}\b',  # Amex
    ],
    "Internal IPs": [
        r'\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b',
    ],
    "Source Code Leaks": [
        r'\.git/', r'\.svn/', r'\.env', r'wp-config\.php', r'config\.php',
    ]
}

def _scan_content(content: str, url: str) -> List[Dict]:
    """Scan content for sensitive patterns"""    findings = []
    
    for category, patterns in SENSITIVE_PATTERNS.items():
        for pattern in patterns:
            matches = re.finditer(pattern, content, re.I | re.M)
            for match in matches:
                # Mask sensitive values in report
                matched_text = match.group(0)
                masked = matched_text[:10] + "..." + matched_text[-4:] if len(matched_text) > 20 else "****"
                
                findings.append({
                    "type": f"Information Leakage ({category})",
                    "url": url,
                    "param": "response_body",
                    "payload": pattern,
                    "evidence": f"Found: {masked}",
                    "severity": "HIGH" if "Key" in category or "Private" in category else "MEDIUM",
                    "timestamp": __import__('time').time()
                })
    
    return findings

def _check_exposed_files(url: str, session: requests.Session) -> List[Dict]:
    """Check for commonly exposed sensitive files"""
    results = []
    sensitive_files = [
        '/.git/config', '/.env', '/wp-config.php', '/config.php',
        '/backup.sql', '/database.sql', '/debug.log', '/error.log',
        '/phpinfo.php', '/server-status', '/.htaccess'
    ]
    
    base_url = f"{__import__('urllib.parse').urlparse(url).scheme}://{__import__('urllib.parse').urlparse(url).netloc}"
    
    for file_path in sensitive_files:
        test_url = base_url + file_path
        try:
            resp = session.get(test_url, timeout=5, allow_redirects=False)
            if resp.status_code == 200 and len(resp.content) > 50:
                results.append({
                    "type": "Exposed Sensitive File",
                    "url": test_url,
                    "param": "N/A",
                    "payload": file_path,
                    "evidence": f"File accessible (Status: {resp.status_code}, Size: {len(resp.content)} bytes)",
                    "severity": "CRITICAL",
                    "timestamp": __import__('time').time()
                })
                print_status(f"🚨 Exposed: {file_path}", "CRITICAL")
        except:
            continue    
    return results

def _check_headers_leak(url: str, session: requests.Session) -> List[Dict]:
    """Check response headers for information leakage"""
    results = []
    try:
        resp = session.head(url, timeout=5)
        headers = resp.headers
        
        # Check for verbose server/version info
        server = headers.get('Server', '')
        if re.search(r'apache/\d|nginx/\d|php/\d|python/\d', server, re.I):
            results.append({
                "type": "Server Version Disclosure",
                "url": url,
                "param": "Server header",
                "payload": server,
                "evidence": f"Server header reveals version: {server}",
                "severity": "LOW",
                "timestamp": __import__('time').time()
            })
        
        # Check for missing security headers
        missing = []
        for header in ['X-Content-Type-Options', 'X-Frame-Options', 'X-XSS-Protection']:
            if header not in headers:
                missing.append(header)
        
        if missing:
            results.append({
                "type": "Missing Security Headers",
                "url": url,
                "param": "response_headers",
                "payload": ", ".join(missing),
                "evidence": f"Missing: {missing}",
                "severity": "MEDIUM",
                "timestamp": __import__('time').time()
            })
            
    except:
        pass
    
    return results

def scan(url: str, session: requests.Session) -> List[Dict]:
    """Main scan function for information leakage"""
    results = []
    
    print_status(f"🔍 Scanning for info leaks: {url[:70]}...", "INFO")    
    try:
        # Get page content
        resp = session.get(url, timeout=config.TIMEOUT)
        content = resp.text
        
        # Scan content
        content_findings = _scan_content(content, url)
        results.extend(content_findings)
        
        # Check headers
        header_findings = _check_headers_leak(url, session)
        results.extend(header_findings)
        
    except requests.RequestException as e:
        logger.warning(f"Could not fetch {url}: {e}")
    
    # Check for exposed files (only on root domain)
    parsed = __import__('urllib.parse').urlparse(url)
    if parsed.path in ['', '/']:
        file_findings = _check_exposed_files(url, session)
        results.extend(file_findings)
    
    # Report findings
    for finding in results:
        severity = finding['severity']
        print_status(f"{'🚨' if severity in ['CRITICAL','HIGH'] else '🔍'} {finding['type']}: {finding['evidence'][:50]}...", 
                    "CRITICAL" if severity == "CRITICAL" else "WARNING" if severity == "HIGH" else "INFO")
    
    return results
