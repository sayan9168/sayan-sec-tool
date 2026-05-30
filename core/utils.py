"""
Utility Functions for Sayan-Sec-Tool
"""
import re
import logging
import json
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode
from colorama import Fore, Style, init

init(autoreset=True)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/scan.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def print_status(msg: str, level: str = "INFO"):
    """Colored console output"""
    colors = {
        "INFO": Fore.CYAN,
        "SUCCESS": Fore.GREEN,
        "WARNING": Fore.YELLOW,
        "ERROR": Fore.RED,
        "CRITICAL": Fore.MAGENTA
    }
    color = colors.get(level, Fore.WHITE)
    print(f"{color}[{level}] {msg}{Style.RESET_ALL}")

def normalize_url(url: str) -> str:
    """Normalize URL for consistent comparison"""
    parsed = urlparse(url)
    # Remove fragments and normalize path
    path = parsed.path.rstrip('/') or '/'
    return f"{parsed.scheme}://{parsed.netloc}{path}"

def extract_params(url: str) -> dict:
    """Extract query parameters from URL"""
    parsed = urlparse(url)
    return parse_qs(parsed.query)

def inject_payload(url: str, param: str, payload: str) -> str:
    """Inject payload into URL parameter"""
    parsed = urlparse(url)    params = parse_qs(parsed.query, keep_blank_values=True)
    
    if param in params:
        params[param] = [payload]
    else:
        params[param] = [payload]
    
    new_query = urlencode(params, doseq=True)
    new_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
    if parsed.fragment:
        new_url += f"#{parsed.fragment}"
    return new_url

def is_valid_url(url: str, base_domain: str) -> bool:
    """Check if URL belongs to target domain"""
    try:
        parsed = urlparse(url)
        return parsed.netloc.endswith(base_domain) or parsed.netloc == base_domain
    except:
        return False

def extract_links(html: str, base_url: str) -> list:
    """Extract all links from HTML content"""
    from bs4 import BeautifulSoup
    soup = BeautifulSoup(html, 'lxml')
    links = []
    
    for tag in soup.find_all('a', href=True):
        href = tag['href']
        # Handle relative URLs
        if href.startswith('http'):
            links.append(href)
        elif href.startswith('//'):
            links.append(f"{urlparse(base_url).scheme}:{href}")
        elif href.startswith('/'):
            links.append(f"{urlparse(base_url).scheme}://{urlparse(base_url).netloc}{href}")
        else:
            base_path = '/'.join(base_url.split('/')[:-1])
            links.append(f"{base_path}/{href}")
    
    return list(set(links))

def save_report(vulns: list, target: str, format: str = 'json'):
    """Save vulnerability report"""
    from config import config
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{config.REPORT_DIR}/{target.replace('://', '_')}_{timestamp}.{format}"
    
    report = {
        "target": target,        "scan_time": datetime.now().isoformat(),
        "tool_version": config.VERSION,
        "vulnerabilities": vulns,
        "total_found": len(vulns)
    }
    
    with open(filename, 'w', encoding='utf-8') as f:
        if format == 'json':
            json.dump(report, f, indent=2, ensure_ascii=False)
    
    print_status(f"Report saved: {filename}", "SUCCESS")
    return filename

def sanitize_output(text: str) -> str:
    """Remove ANSI codes for file output"""
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)
