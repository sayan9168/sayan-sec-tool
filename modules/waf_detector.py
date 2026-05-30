import requests
from typing import Optional, List
from core.utils import logger, print_status

# WAF Signatures Database (Headers & Content)
WAF_SIGNATURES = {
    "Cloudflare": {
        "headers": ["cf-ray", "cf-request-id", "server: cloudflare"],
        "content": ["Cloudflare Ray ID", "Checking your browser"]
    },
    "AWS WAF": {
        "headers": ["x-amzn-requestid", "x-amzn-waf"],
        "content": ["AWS WAF", "Forbidden by AWS WAF"]
    },
    "ModSecurity": {
        "headers": ["mod_security", "modsecurity"],
        "content": ["ModSecurity", "Access Denied", "403 Forbidden"]
    },
    "Barracuda": {
        "headers": ["barra_counter_session", "barracuda_"],
        "content": ["Barracuda Networks"]
    },
    "F5 BIG-IP": {
        "headers": ["f5_st", "mrhsession", "bigip"],
        "content": ["F5 BIG-IP"]
    },
    "Imperva (Incapsula)": {
        "headers": ["incap_ses", "visid_incap", "x-cdn: incapsula"],
        "content": ["Incapsula", "Imperva"]
    },
    "Akamai": {
        "headers": ["x-akamai-transformed", "akamai"],
        "content": ["Akamai"]
    }
}

class WAFDetector:
    def __init__(self, session: requests.Session):
        self.session = session
    
    def detect(self, url: str) -> Optional[str]:
        """Detect WAF presence based on headers and response content"""
        try:
            # 1. Check Headers via HEAD request
            resp = self.session.head(url, timeout=5, allow_redirects=True)
            headers_text = " ".join([f"{k}: {v}" for k, v in resp.headers.items()]).lower()
            
            for waf_name, sigs in WAF_SIGNATURES.items():
                if any(h.lower() in headers_text for h in sigs["headers"]):
                    print_status(f"🛡️ WAF Detected: {waf_name} (via Headers)", "WARNING")
                    return waf_name
            
            # 2. Check Content via GET request (if headers didn't match)
            # Using a benign payload to trigger WAF challenge page
            test_url = f"{url}?__test_waf__=1"
            resp = self.session.get(test_url, timeout=5)
            content_text = resp.text.lower()
            
            for waf_name, sigs in WAF_SIGNATURES.items():
                if any(c.lower() in content_text for c in sigs["content"]):
                    print_status(f"️ WAF Detected: {waf_name} (via Content/Challenge)", "WARNING")
                    return waf_name
            
            # 3. Check for generic challenges (CAPTCHA, 403 with challenge text)
            if resp.status_code == 403 and any(kw in content_text for kw in ["captcha", "verify", "security check"]):
                print_status("⚠️ Potential WAF/Challenge Page detected (Generic)", "WARNING")
                return "Generic WAF/Challenge"

            print_status("✅ No WAF detected", "INFO")
            return None
            
        except requests.RequestException as e:
            logger.error(f"WAF Detection failed for {url}: {e}")
            return None
