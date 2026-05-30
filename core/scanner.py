"""
Core Vulnerability Scanner Module
"""
import requests
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional
from .utils import (
    logger, print_status, normalize_url, 
    extract_links, is_valid_url, save_report
)
from config import config

class WebScanner:
    """Multi-threaded web vulnerability scanner"""
    
    def __init__(self, target: str, max_depth: int = None):
        self.target = normalize_url(target)
        self.base_domain = urlparse(self.target).netloc
        self.max_depth = max_depth or config.MAX_DEPTH
        self.visited = set()
        self.to_visit = [self.target]
        self.vulns: List[Dict] = []
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': config.USER_AGENT})
        self.session.verify = config.VERIFY_SSL
        
    def _get_robots_paths(self) -> List[str]:
        """Parse robots.txt for interesting paths"""
        paths = []
        try:
            resp = self.session.get(f"{urlparse(self.target).scheme}://{self.base_domain}/robots.txt", timeout=5)
            for line in resp.text.split('\n'):
                if line.strip().startswith('Disallow:'):
                    path = line.split(':', 1)[1].strip()
                    if path and path != '/':
                        paths.append(path)
        except:
            pass
        return paths
    
    def crawl(self, url: str = None, depth: int = 0) -> List[str]:
        """Crawl website and collect URLs"""
        url = url or self.target
        url = normalize_url(url)
        
        if depth > self.max_depth or url in self.visited:
            return []
                self.visited.add(url)
        found_links = []
        
        try:
            print_status(f"Crawling: {url}", "INFO")
            resp = self.session.get(url, timeout=config.TIMEOUT, allow_redirects=config.FOLLOW_REDIRECTS)
            
            if 'text/html' not in resp.headers.get('Content-Type', ''):
                return []
            
            # Extract links
            links = extract_links(resp.text, url)
            for link in links:
                if is_valid_url(link, self.base_domain) and normalize_url(link) not in self.visited:
                    found_links.append(normalize_url(link))
                    self.to_visit.append(normalize_url(link))
            
            # Check robots.txt on first crawl
            if depth == 0:
                robots_paths = self._get_robots_paths()
                for path in robots_paths:
                    robot_url = f"{urlparse(self.target).scheme}://{self.base_domain}{path}"
                    if robot_url not in self.visited:
                        found_links.append(robot_url)
                        
        except requests.RequestException as e:
            logger.error(f"Error crawling {url}: {e}")
            print_status(f"Error: {url} - {e}", "ERROR")
        
        return found_links
    
    def run_full_scan(self, modules: list = None) -> List[Dict]:
        """Execute full vulnerability scan"""
        print_status(f"🚀 Starting scan on {self.target}", "INFO")
        print_status(f"Max depth: {self.max_depth}, Threads: {config.MAX_THREADS}", "INFO")
        
        # Phase 1: Crawl
        print_status("📡 Phase 1: Crawling...", "INFO")
        while self.to_visit:
            current = self.to_visit.pop(0)
            if current not in self.visited:
                self.crawl(current, depth=0)  # Simplified depth tracking
        
        print_status(f"✅ Crawled {len(self.visited)} URLs", "SUCCESS")
        
        # Phase 2: Scan with modules
        print_status("🔬 Phase 2: Vulnerability Scanning...", "INFO")
        
        if modules is None:
            from modules import sqli_detector, xss_detector, info_leak            modules = [sqli_detector, xss_detector, info_leak]
        
        with ThreadPoolExecutor(max_workers=config.MAX_THREADS) as executor:
            futures = []
            for url in self.visited:
                for module in modules:
                    if hasattr(module, 'scan'):
                        futures.append(executor.submit(module.scan, url, self.session))
            
            for future in as_completed(futures):
                try:
                    results = future.result()
                    if results:
                        self.vulns.extend(results)
                except Exception as e:
                    logger.error(f"Module error: {e}")
        
        # Summary
        print_status(f"📊 Scan Complete! Found {len(self.vulns)} potential issues", "SUCCESS")
        for vuln in self.vulns:
            print_status(f"  • [{vuln['severity']}] {vuln['type']}: {vuln['url'][:60]}...", 
                        "WARNING" if vuln['severity'] == 'HIGH' else "INFO")
        
        return self.vulns
    
    def get_summary(self) -> Dict:
        """Get scan summary"""
        from collections import Counter
        severity_count = Counter(v['severity'] for v in self.vulns)
        type_count = Counter(v['type'] for v in self.vulns)
        
        return {
            "target": self.target,
            "urls_scanned": len(self.visited),
            "total_vulns": len(self.vulns),
            "by_severity": dict(severity_count),
            "by_type": dict(type_count)
  }
