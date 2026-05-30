#!/usr/bin/env python3
"""
Sayan-Sec-Tool: Advanced Educational Web Security Research Framework
Author: sayan9168 (CEH)
Purpose: Learning, Research, and Authorized Testing Only

⚠️ LEGAL DISCLAIMER:
This tool is for educational purposes only. 
Always obtain written permission before testing any system.
Unauthorized access is illegal and punishable by law.
"""
import sys
import argparse
import os
from config import config, Config
from core.utils import print_status, save_report, config as utils_config

def banner():
    """Display tool banner"""
    print(f"""
╔═══════════════════════════════════════════════════════════╗
║  🔬 {config.TOOL_NAME} v{config.VERSION}                      
║  Advanced Web Security Research Framework              
║  Author: {config.AUTHOR}                                    
║  ⚠️  AUTHORIZED USE ONLY - CEH Learning Project          
╚═══════════════════════════════════════════════════════════╝
    """)

def cli_mode(args):
    """Run in command-line mode with all advanced features"""
    from core.scanner import WebScanner
    
    # Initialize
    config.ensure_dirs()
    print_status(f"🎯 Target: {args.target}", "INFO")
    print_status(f"📡 Mode: {args.mode.upper()}", "INFO")
    
    # Select modules based on arguments
    modules = []
    module_names = []
    
    # Core Vulnerability Modules
    if args.sqli or args.all:
        from modules import sqli_detector
        modules.append(sqli_detector)
        module_names.append("SQLi")
        print_status("✓ SQL Injection module loaded", "INFO")
    if args.xss or args.all:
        from modules import xss_detector
        modules.append(xss_detector)        module_names.append("XSS")
        print_status("✓ XSS Detection module loaded", "INFO")
    if args.info or args.all:
        from modules import info_leak
        modules.append(info_leak)
        module_names.append("InfoLeak")
        print_status("✓ Info Leakage module loaded", "INFO")
    
    # Advanced Security Modules
    if args.waf or args.all:
        from modules import waf_detector
        modules.append(waf_detector)
        module_names.append("WAF")
        print_status("✓ WAF Detection module loaded", "INFO")
    if args.headers or args.all:
        from modules import headers_analyzer
        modules.append(headers_analyzer)
        module_names.append("Headers")
        print_status("✓ Security Headers module loaded", "INFO")
    if args.api or args.all:
        from modules import api_scanner
        modules.append(api_scanner)
        module_names.append("API")
        print_status("✓ API Security module loaded", "INFO")
    if args.auth or args.all:
        from modules import auth_testing
        modules.append(auth_testing)
        module_names.append("Auth")
        print_status("✓ Auth Testing module loaded", "INFO")
    if args.compliance or args.all:
        from modules import compliance_checker
        modules.append(compliance_checker)
        module_names.append("Compliance")
        print_status("✓ Compliance Checker module loaded", "INFO")
    if args.recon or args.all:
        from modules import recon
        modules.append(recon)
        module_names.append("Recon")
        print_status("✓ Reconnaissance module loaded", "INFO")
    
    if not modules:
        print_status("❌ No modules selected. Use --all or specify modules.", "ERROR")
        print_status("Available: --sqli --xss --info --waf --headers --api --auth --compliance --recon --all", "INFO")
        return 1
    
    print_status(f"📦 Loaded modules: {', '.join(module_names)}", "SUCCESS")
    
    # Configure scanner options
    scanner_opts = {
        "max_depth": args.depth,        "max_threads": args.threads,
        "timeout": args.timeout,
        "cvss_scoring": args.cvss,
        "compliance_standards": args.compliance_standards.split(',') if args.compliance_standards else None
    }
    
    # Run scan
    print_status("🚀 Starting security scan...", "INFO")
    scanner = WebScanner(args.target, **scanner_opts)
    vulns = scanner.run_full_scan(modules)
    
    # Post-scan processing
    if args.cvss:
        from core.cvss import CVSSCalculator
        print_status("📊 Calculating CVSS scores...", "INFO")
        for vuln in vulns:
            if 'score' not in vuln:
                metrics = CVSSCalculator.get_recommended_metrics(vuln.get('type', 'Info Leak'))
                score, severity = CVSSCalculator.calculate(metrics)
                vuln['cvss_score'] = score
                if severity != vuln.get('severity'):
                    vuln['original_severity'] = vuln['severity']
                    vuln['severity'] = severity
    
    # Save report if requested
    if args.report:
        report_format = args.report_format
        filename = save_report(vulns, args.target, format=report_format)
        print_status(f"📄 Report saved: {filename}", "SUCCESS")
    
    if args.export:
        from core.exporter import Exporter
        exporter = Exporter(vulns, args.target)
        if args.export == 'pdf':
            exporter.to_pdf(args.export_path or "reports/")
        elif args.export == 'html':
            exporter.to_html(args.export_path or "reports/")
        print_status(f"📤 Exported to {args.export} format", "SUCCESS")
    
    # Summary statistics
    if vulns:
        from collections import Counter
        severity_count = Counter(v['severity'] for v in vulns)
        type_count = Counter(v['type'] for v in vulns)
        
        print_status("\n📊 SCAN SUMMARY", "INFO")
        print_status(f"  Total URLs Scanned: {len(scanner.visited)}", "INFO")
        print_status(f"  Total Findings: {len(vulns)}", "INFO")
        print_status(f"  By Severity:", "INFO")
        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:            if severity_count.get(sev):
                icon = "🚨" if sev == "CRITICAL" else "⚠️" if sev == "HIGH" else "🔍"
                print_status(f"    {icon} {sev}: {severity_count[sev]}", 
                           "CRITICAL" if sev == "CRITICAL" else "WARNING" if sev == "HIGH" else "INFO")
        
        if args.verbose:
            print_status(f"  By Type:", "INFO")
            for vtype, count in type_count.most_common(5):
                print_status(f"    • {vtype}: {count}", "INFO")
    
    # Exit code based on findings
    critical = sum(1 for v in vulns if v['severity'] == 'CRITICAL')
    high = sum(1 for v in vulns if v['severity'] == 'HIGH')
    
    if critical > 0:
        print_status(f"\n🚨 {critical} CRITICAL issues found! Review immediately.", "CRITICAL")
        return 2
    elif high > 0:
        print_status(f"\n⚠️  {high} HIGH severity issues found", "WARNING")
        return 1
    
    print_status("\n✅ Scan complete - No critical issues found", "SUCCESS")
    return 0

def proxy_mode(args):
    """Run MITM proxy mode with advanced traffic analysis"""
    print_status("🔌 Starting MITM Proxy Mode", "INFO")
    print_status(f"📍 Listening on {config.PROXY_HOST}:{args.port}", "INFO")
    print_status("🌐 Configure browser proxy: 127.0.0.1:{}".format(args.port), "INFO")
    print_status("🔐 Install mitmproxy CA cert for HTTPS interception", "INFO")
    print_status("⚠️  Press Ctrl+C to stop\n", "WARNING")
    
    # Launch mitmproxy with our addon
    import subprocess
    cmd = [
        sys.executable, "-m", "mitmproxy",
        "-s", "core/proxy.py",
        "--listen-host", config.PROXY_HOST,
        "--listen-port", str(args.port),
        "--set", f"ssl_insecure={not config.VERIFY_SSL}",
        "--set", f"flow_detail={2 if args.verbose else 1}"
    ]
    
    if args.waf:
        cmd.extend(["--set", "addons.waf_detection=true"])
    if args.headers:
        cmd.extend(["--set", "addons.header_analysis=true"])
    
    try:
        subprocess.run(cmd)    except KeyboardInterrupt:
        print_status("\n✅ Proxy stopped gracefully", "INFO")
    except Exception as e:
        print_status(f"❌ Proxy error: {e}", "ERROR")
        return 1
    return 0

def gui_mode(args):
    """Launch GUI mode"""
    print_status("🖥️  Launching Graphical Interface...", "INFO")
    try:
        from ui.gui import launch_gui
        launch_gui()
        return 0
    except ImportError:
        print_status("❌ GUI dependencies missing. Install: pip install PyQt5", "ERROR")
        return 1
    except Exception as e:
        print_status(f"❌ GUI error: {e}", "ERROR")
        return 1

def list_modules(args):
    """List all available modules with descriptions"""
    modules_info = {
        "sqli": "SQL Injection Detection (Error/Time/Union-based)",
        "xss": "Cross-Site Scripting Detection (Reflected/DOM-based)",
        "info": "Sensitive Information Leakage Detection",
        "waf": "WAF/IPS Detection & Analysis",
        "headers": "Security Headers Audit & Grading",
        "api": "REST API Security Testing (CORS, Docs, Auth)",
        "auth": "Authentication & Session Security Testing",
        "compliance": "OWASP/PCI-DSS/GDPR Compliance Checking",
        "recon": "Passive Reconnaissance & Tech Fingerprinting"
    }
    
    print(f"\n{'='*60}")
    print(f"📦 Available Modules for {config.TOOL_NAME}")
    print(f"{'='*60}\n")
    
    for name, desc in modules_info.items():
        flag = f"--{name}"
        print(f"  {flag:<12} {desc}")
    
    print(f"\n💡 Use '--all' to enable all modules")
    print(f"💡 Use '--help' for more options\n")
    return 0

def main():
    """Main entry point with full feature support"""
    parser = argparse.ArgumentParser(        description=f"{config.TOOL_NAME} - Advanced Educational Security Research Tool",
        epilog="⚠️ Use responsibly and only on systems you own or have permission to test.",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Positional arguments
    parser.add_argument('target', nargs='?', help='Target URL to scan')
    
    # Operation mode
    parser.add_argument('-m', '--mode', choices=['scan', 'proxy', 'gui', 'list'], 
                       default='scan', help='Operation mode (default: scan)')
    
    # Global options
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('-q', '--quiet', action='store_true', help='Minimal output mode')
    parser.add_argument('--version', action='version', version=f"{config.TOOL_NAME} v{config.VERSION}")
    
    # Scan options group
    scan_group = parser.add_argument_group('🔍 Scan Options')
    scan_group.add_argument('-d', '--depth', type=int, default=config.MAX_DEPTH,
                           help=f'Crawl depth (default: {config.MAX_DEPTH})')
    scan_group.add_argument('-t', '--threads', type=int, default=config.MAX_THREADS,
                           help=f'Concurrent threads (default: {config.MAX_THREADS})')
    scan_group.add_argument('--timeout', type=int, default=config.TIMEOUT,
                           help=f'Request timeout in seconds (default: {config.TIMEOUT})')
    scan_group.add_argument('-u', '--user-agent', type=str, default=config.USER_AGENT,
                           help='Custom User-Agent string')
    
    # Module selection group
    module_group = parser.add_argument_group('🧩 Module Selection')
    module_group.add_argument('--sqli', action='store_true', help='Enable SQL injection detection')
    module_group.add_argument('--xss', action='store_true', help='Enable XSS detection')
    module_group.add_argument('--info', action='store_true', help='Enable info leakage detection')
    module_group.add_argument('--waf', action='store_true', help='Enable WAF detection')
    module_group.add_argument('--headers', action='store_true', help='Enable security headers analysis')
    module_group.add_argument('--api', action='store_true', help='Enable API security testing')
    module_group.add_argument('--auth', action='store_true', help='Enable auth/session testing')
    module_group.add_argument('--compliance', action='store_true', help='Enable compliance checking')
    module_group.add_argument('--recon', action='store_true', help='Enable reconnaissance')
    module_group.add_argument('--all', action='store_true', help='Enable ALL detection modules')
    module_group.add_argument('--list-modules', action='store_true', help='List all available modules')
    
    # Reporting options
    report_group = parser.add_argument_group('📊 Reporting Options')
    report_group.add_argument('-r', '--report', action='store_true', help='Save scan report')
    report_group.add_argument('--report-format', choices=['json', 'html', 'pdf', 'markdown'], 
                           default='json', help='Report format (default: json)')
    report_group.add_argument('--export', choices=['pdf', 'html'], help='Export report in specific format')
    report_group.add_argument('--export-path', type=str, help='Export directory path')
    report_group.add_argument('--cvss', action='store_true', help='Calculate CVSS v3.1 scores')    
    # Compliance options
    compliance_group = parser.add_argument_group('📋 Compliance Options')
    compliance_group.add_argument('--compliance-standards', type=str, 
                                 default='OWASP,PCI-DSS',
                                 help='Compliance standards to check (comma-separated)')
    
    # Proxy options
    proxy_group = parser.add_argument_group('🌐 Proxy Options')
    proxy_group.add_argument('-p', '--port', type=int, default=config.PROXY_PORT,
                            help=f'Proxy port (default: {config.PROXY_PORT})')
    
    # Parse arguments
    args = parser.parse_args()
    
    # Show banner (unless quiet mode)
    if not args.quiet:
        banner()
    
    # Handle list-modules mode
    if args.mode == 'list' or args.list_modules:
        return list_modules(args)
    
    # Validate target for scan/proxy mode
    if args.mode in ['scan', 'proxy'] and not args.target:
        parser.error("Target URL is required for scan/proxy mode")
    
    # Update config with CLI options
    if args.user_agent:
        config.USER_AGENT = args.user_agent
    if args.port:
        config.PROXY_PORT = args.port
    if args.verbose:
        import logging
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Route to appropriate mode
    try:
        if args.mode == 'gui':
            return gui_mode(args)
        elif args.mode == 'proxy':
            return proxy_mode(args)
        else:
            return cli_mode(args)
    except KeyboardInterrupt:
        print_status("\n⚠️  Interrupted by user", "WARNING")
        return 130
    except ImportError as e:
        print_status(f"❌ Missing dependency: {e}", "ERROR")
        print_status("💡 Install with: pip install -r requirements.txt", "INFO")        return 1
    except Exception as e:
        print_status(f"❌ Error: {e}", "ERROR")
        if utils_config and hasattr(utils_config, 'logger'):
            utils_config.logger.exception("Unhandled exception")
        return 1

if __name__ == "__main__":
    sys.exit(main())
