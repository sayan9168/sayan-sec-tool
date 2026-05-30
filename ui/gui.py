"""
Basic GUI Module using Tkinter
Educational Purpose Only
"""
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from threading import Thread
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.scanner import WebScanner
from core.utils import print_status, save_report
from config import config

class SayanSecGUI:
    """Simple GUI for Sayan-Sec-Tool"""
    
    def __init__(self, root):
        self.root = root
        self.root.title(f"{config.TOOL_NAME} v{config.VERSION} - Educational Research Tool")
        self.root.geometry("900x600")
        self.root.minsize(800, 500)
        
        # Configure style
        self._setup_style()
        self._create_widgets()
        
    def _setup_style(self):
        """Configure ttk styles"""
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('Header.TLabel', font=('Helvetica', 14, 'bold'))
        style.configure('Status.TLabel', foreground='blue')
        
    def _create_widgets(self):
        """Create GUI widgets"""
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Title
        title = ttk.Label(
            main_frame, 
            text=f"🔬 {config.TOOL_NAME} v{config.VERSION}\n⚠️ Educational Use Only",
            style='Header.TLabel',
            justify=tk.CENTER
        )        title.grid(row=0, column=0, columnspan=3, pady=(0, 10))
        
        # Target URL input
        ttk.Label(main_frame, text="Target URL:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.url_var = tk.StringVar(value="http://testphp.vulnweb.com")  # Demo target
        url_entry = ttk.Entry(main_frame, textvariable=self.url_var, width=60)
        url_entry.grid(row=1, column=1, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        # Options
        ttk.Label(main_frame, text="Max Depth:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.depth_var = tk.IntVar(value=2)
        depth_spin = ttk.Spinbox(main_frame, from_=1, to=5, textvariable=self.depth_var, width=5)
        depth_spin.grid(row=2, column=1, sticky=tk.W, pady=5)
        
        # Module checkboxes
        ttk.Label(main_frame, text="Modules:").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.sqli_var = tk.BooleanVar(value=True)
        self.xss_var = tk.BooleanVar(value=True)
        self.info_var = tk.BooleanVar(value=True)
        
        ttk.Checkbutton(main_frame, text="SQL Injection", variable=self.sqli_var).grid(row=3, column=1, sticky=tk.W)
        ttk.Checkbutton(main_frame, text="XSS Detection", variable=self.xss_var).grid(row=3, column=2, sticky=tk.W)
        ttk.Checkbutton(main_frame, text="Info Leakage", variable=self.info_var).grid(row=4, column=1, sticky=tk.W)
        
        # Control buttons
        btn_frame = ttk.Frame(main_frame)
        btn_frame.grid(row=5, column=0, columnspan=3, pady=10)
        
        self.start_btn = ttk.Button(btn_frame, text="🚀 Start Scan", command=self._start_scan)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(btn_frame, text="📁 Save Report", command=self._save_report).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="❌ Exit", command=self.root.quit).pack(side=tk.LEFT, padx=5)
        
        # Output console
        ttk.Label(main_frame, text="Output Console:").grid(row=6, column=0, sticky=tk.W, pady=(10, 5))
        self.console = scrolledtext.ScrolledText(main_frame, height=15, state='disabled')
        self.console.grid(row=7, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        
        # Progress bar
        self.progress = ttk.Progressbar(main_frame, mode='indeterminate')
        self.progress.grid(row=8, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 5))
        
        # Status bar
        self.status_var = tk.StringVar(value="Ready - Enter target URL and click Start")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, style='Status.TLabel', relief=tk.SUNKEN)
        status_bar.grid(row=9, column=0, columnspan=3, sticky=(tk.W, tk.E))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(7, weight=1)
        
    def _log(self, message: str, level: str = "INFO"):
        """Add message to console"""
        self.console.config(state='normal')
        prefix = {
            "INFO": "[ℹ️]", "SUCCESS": "[✅]", 
            "WARNING": "[⚠️]", "ERROR": "[❌]", "CRITICAL": "[🚨]"
        }.get(level, "[•]")
        self.console.insert(tk.END, f"{prefix} {message}\n")
        self.console.see(tk.END)
        self.console.config(state='disabled')
        
    def _start_scan(self):
        """Start scan in background thread"""
        target = self.url_var.get().strip()
        if not target.startswith(('http://', 'https://')):
            messagebox.showerror("Error", "URL must start with http:// or https://")
            return
            
        # Disable button during scan
        self.start_btn.config(state='disabled')
        self.progress.start(10)
        self.status_var.set(f"Scanning: {target}")
        
        # Run scan in thread
        thread = Thread(target=self._run_scan, args=(target,), daemon=True)
        thread.start()
        
    def _run_scan(self, target: str):
        """Execute scan logic"""
        try:
            from core.scanner import WebScanner
            
            scanner = WebScanner(target, max_depth=self.depth_var.get())
            
            # Select modules
            modules = []
            if self.sqli_var.get():
                from modules import sqli_detector
                modules.append(sqli_detector)
            if self.xss_var.get():
                from modules import xss_detector
                modules.append(xss_detector)
            if self.info_var.get():
                from modules import info_leak
                modules.append(info_leak)
                        # Override print_status to log to GUI
            def gui_print(msg, level="INFO"):
                self.root.after(0, lambda: self._log(msg, level))
            
            # Monkey patch for demo
            import core.utils
            core.utils.print_status = gui_print
            
            vulns = scanner.run_full_scan(modules if modules else None)
            
            # Update GUI with results
            self.root.after(0, lambda: self._on_scan_complete(scanner, vulns))
            
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Scan Error", str(e)))
            self.root.after(0, lambda: self.status_var.set("Error occurred"))
        finally:
            self.root.after(0, lambda: self.progress.stop())
            self.root.after(0, lambda: self.start_btn.config(state='normal'))
    
    def _on_scan_complete(self, scanner, vulns):
        """Handle scan completion"""
        summary = scanner.get_summary()
        self._log(f"\n✅ Scan Complete!", "SUCCESS")
        self._log(f"URLs Scanned: {summary['urls_scanned']}", "INFO")
        self._log(f"Vulnerabilities Found: {summary['total_vulns']}", 
                 "WARNING" if summary['total_vulns'] > 0 else "SUCCESS")
        
        if vulns:
            self._log("\n📋 Findings:", "INFO")
            for v in vulns[:10]:  # Show first 10
                self._log(f"  • [{v['severity']}] {v['type']}: {v['url'][:50]}...", 
                         "WARNING" if v['severity'] in ['HIGH','CRITICAL'] else "INFO")
            if len(vulns) > 10:
                self._log(f"  ... and {len(vulns) - 10} more", "INFO")
        
        self.status_var.set(f"Complete - {summary['total_vulns']} issues found")
        self.vulns = vulns  # Store for report
        
    def _save_report(self):
        """Save scan report"""
        if not hasattr(self, 'vulns'):
            messagebox.showinfo("Info", "Run a scan first to generate a report")
            return
            
        target = self.url_var.get().strip().replace('://', '_').replace('/', '_')
        filename = save_report(self.vulns, target)
        messagebox.showinfo("Report Saved", f"Report saved to:\n{filename}")
        self._log(f"📄 Report saved: {filename}", "SUCCESS")
def launch_gui():
    """Launch the GUI application"""
    from config import config
    config.ensure_dirs()
    
    root = tk.Tk()
    app = SayanSecGUI(root)
    root.mainloop()

if __name__ == "__main__":
    launch_gui()
