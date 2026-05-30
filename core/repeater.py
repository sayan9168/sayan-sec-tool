"""
Request Repeater Module - Manual Request Testing
"""
import requests
from urllib.parse import urlparse, parse_qs, urlencode
from typing import Dict, Optional, Union
from .utils import logger, print_status
from config import config

class RequestRepeater:
    """Manual request modification and replay tool"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': config.USER_AGENT})
        self.session.verify = config.VERIFY_SSL
        self.history = []
    
    def build_request(
        self,
        url: str,
        method: str = "GET",
        headers: Dict = None,
        params: Dict = None,
        data: Union[Dict, str] = None,
        json_data: Dict = None
    ) -> requests.PreparedRequest:
        """Build a prepared request"""
        req = requests.Request(
            method=method.upper(),
            url=url,
            headers=headers,
            params=params,
            data=data,
            json=json_data
        )
        return self.session.prepare_request(req)
    
    def send(
        self,
        url: str,
        method: str = "GET",
        headers: Dict = None,
        params: Dict = None,
        data: Union[Dict, str] = None,
        timeout: int = None
    ) -> Dict:
        """Send request and return formatted response"""
        timeout = timeout or config.TIMEOUT
                try:
            print_status(f"→ {method} {url}", "INFO")
            
            resp = self.session.request(
                method=method,
                url=url,
                headers=headers,
                params=params,
                data=data,
                timeout=timeout,
                allow_redirects=config.FOLLOW_REDIRECTS
            )
            
            result = {
                "success": True,
                "status_code": resp.status_code,
                "headers": dict(resp.headers),
                "body": resp.text,
                "content_length": len(resp.content),
                "response_time": resp.elapsed.total_seconds(),
                "url": resp.url
            }
            
            self.history.append(result)
            print_status(f"← {resp.status_code} ({resp.elapsed.total_seconds():.2f}s)", 
                        "SUCCESS" if resp.ok else "WARNING")
            
            return result
            
        except requests.RequestException as e:
            error_result = {
                "success": False,
                "error": str(e),
                "url": url
            }
            print_status(f"✗ Request failed: {e}", "ERROR")
            return error_result
    
    def fuzz_param(
        self,
        url: str,
        param_name: str,
        payloads: list,
        method: str = "GET"
    ) -> list:
        """Fuzz a specific parameter with payloads"""
        results = []
        parsed = urlparse(url)
        base_params = parse_qs(parsed.query, keep_blank_values=True)
                for payload in payloads:
            test_params = base_params.copy()
            test_params[param_name] = [payload]
            
            query = urlencode(test_params, doseq=True)
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query}"
            
            result = self.send(test_url, method=method)
            result['payload'] = payload
            result['param'] = param_name
            results.append(result)
            
            # Simple anomaly detection
            if result['success']:
                if result['status_code'] != 200 or result['content_length'] > 10000:
                    print_status(f"🔍 Anomaly detected with payload: {payload[:50]}...", "WARNING")
        
        return results
    
    def compare_responses(self, resp1: Dict, resp2: Dict) -> Dict:
        """Compare two responses for differences"""
        return {
            "status_diff": resp1.get('status_code') != resp2.get('status_code'),
            "length_diff": abs(
                resp1.get('content_length', 0) - resp2.get('content_length', 0)
            ),
            "time_diff": abs(
                resp1.get('response_time', 0) - resp2.get('response_time', 0)
            )
        }
    
    def export_history(self, filename: str = "repeater_history.json"):
        """Export request history to file"""
        import json
        with open(filename, 'w') as f:
            json.dump(self.history, f, indent=2)
        print_status(f"History saved to {filename}", "SUCCESS")
