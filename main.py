#!/usr/bin/env python3
"""
Sayan-Sec-Tool: Educational Web Security Research Framework
Author: sayan9168 (CEH)
Purpose: Learning, Research, and Authorized Testing Only

⚠️ LEGAL DISCLAIMER:
This tool is for educational purposes only. 
Always obtain written permission before testing any system.
Unauthorized access is illegal and punishable by law.
"""
import sys
import argparse
from config import config, Config
from core.utils import print_status, save_report, config as utils_config

def banner():
    """Display tool banner"""
    print(f"""
╔═══════════════════════════════════════════════════════════╗
║  🔬 {config.TOOL_NAME} v{config.VERSION}                      
║  Educational Web Security Research Framework              
║  Author: {config.AUTHOR}                                    
║  ⚠️  AUTHORIZED USE ONLY - CEH Learning Project          
╚═══════════════════════════════════════════════════════════╝
    """)

def cli_mode(args):
    """Run in command-line mode"""
    from core.scanner import WebScanner
    
    # Initialize
    config.ensure_dirs()
    print_status(f"Target: {args.target}", "INFO")
    
    # Select modules
    modules = []
    if args.sqli or args.all:
        from modules import sqli_detector
        modules.append(sqli_detector)
        print_status("✓ SQL Injection module loaded", "INFO")
    if args.xss or args.all:
        from modules import xss_detector
        modules.append(xss_detector)
        print_status("✓ XSS Detection module loaded", "INFO")
    if args.info or args.all:
        from modules import info_leak
        modules.append(info_leak)
        print_status("✓ Info Leakage module loaded", "INFO")
        if not modules:
        print_status("No modules selected. Use --all or specify modules.", "ERROR")
        return 1
    
    # Run scan
    scanner = WebScanner(args.target, max_depth=args.depth)
    vulns = scanner.run_full_scan(modules)
    
    # Save report if requested
    if args.report:
        save_report(vulns, args.target)
    
    # Exit code based on findings
    critical = sum(1 for v in vulns if v['severity'] == 'CRITICAL')
    high = sum(1 for v in vulns if v['severity'] == 'HIGH')
    
    if critical > 0:
        print_status(f"🚨 {critical} CRITICAL issues found!", "CRITICAL")
        return 2
    elif high > 0:
        print_status(f"⚠️  {high} HIGH severity issues found", "WARNING")
        return 1
    
    print_status("✅ Scan complete - No critical issues", "SUCCESS")
    return 0

def proxy_mode(args):
    """Run MITM proxy mode"""
    print_status("🔌 Starting MITM Proxy Mode", "INFO")
    print_status(f"Listening on {config.PROXY_HOST}:{config.PROXY_PORT}", "INFO")
    print_status("Configure browser proxy settings to use this tool")
    print_status("Press Ctrl+C to stop\n", "WARNING")
    
    # Launch mitmproxy with our addon
    import subprocess
    cmd = [
        sys.executable, "-m", "mitmproxy",
        "-s", "core/proxy.py",
        "--listen-host", config.PROXY_HOST,
        "--listen-port", str(config.PROXY_PORT),
        "--set", f"ssl_insecure={not config.VERIFY_SSL}"
    ]
    
    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        print_status("\nProxy stopped", "INFO")

def gui_mode(args):
    """Launch GUI mode"""    print_status("🖥️  Launching GUI...", "INFO")
    from ui.gui import launch_gui
    launch_gui()

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description=f"{config.TOOL_NAME} - Educational Security Research Tool",
        epilog="⚠️ Use responsibly and only on systems you own or have permission to test."
    )
    
    parser.add_argument('target', nargs='?', help='Target URL to scan')
    parser.add_argument('-m', '--mode', choices=['scan', 'proxy', 'gui'], 
                       default='scan', help='Operation mode (default: scan)')
    
    # Scan options
    scan_group = parser.add_argument_group('Scan Options')
    scan_group.add_argument('-d', '--depth', type=int, default=config.MAX_DEPTH,
                           help=f'Crawl depth (default: {config.MAX_DEPTH})')
    scan_group.add_argument('--sqli', action='store_true', help='Enable SQL injection detection')
    scan_group.add_argument('--xss', action='store_true', help='Enable XSS detection')
    scan_group.add_argument('--info', action='store_true', help='Enable info leakage detection')
    scan_group.add_argument('--all', action='store_true', help='Enable all detection modules')
    scan_group.add_argument('-r', '--report', action='store_true', help='Save JSON report')
    
    # Proxy options
    proxy_group = parser.add_argument_group('Proxy Options')
    proxy_group.add_argument('-p', '--port', type=int, default=config.PROXY_PORT,
                            help=f'Proxy port (default: {config.PROXY_PORT})')
    
    args = parser.parse_args()
    
    # Show banner
    banner()
    
    # Validate target for scan mode
    if args.mode == 'scan' and not args.target:
        parser.error("Target URL is required for scan mode")
    
    # Update config if needed
    if args.port:
        config.PROXY_PORT = args.port
    
    # Route to appropriate mode
    try:
        if args.mode == 'gui':
            gui_mode(args)
        elif args.mode == 'proxy':
            proxy_mode(args)
        else:            return cli_mode(args)
    except KeyboardInterrupt:
        print_status("\n⚠️  Interrupted by user", "WARNING")
        return 130
    except Exception as e:
        print_status(f"❌ Error: {e}", "ERROR")
        if utils_config:
            utils_config.logger.exception("Unhandled exception")
        return 1

if __name__ == "__main__":
    sys.exit(main())
