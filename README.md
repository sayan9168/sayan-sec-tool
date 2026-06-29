# 🔬 Sayan-Sec-Tool

> ⚠️ **EDUCATIONAL USE ONLY** | Authorized Testing Only | CEH Learning Project

Advanced web security research framework built with Python. Designed for learning ethical hacking, vulnerability assessment, and security research.

## 🎯 Purpose
- 📚 Learn web security concepts hands-on
- 🔍 Practice vulnerability detection techniques  
- 🧪 Research security mechanisms in controlled environments
- 💼 Build portfolio for cybersecurity career

## ⚠️ Legal Disclaimer
This tool is for EDUCATIONAL and RESEARCH purposes only.

✅ DO:
- Use on your own systems/labs
- Test on intentionally vulnerable apps (DVWA, WebGoat, etc.)
- Use in CTF competitions
- Test with written authorization

❌ DON'T:
- Scan systems without explicit permission
- Use for malicious purposes
- Attack production systems
- Violate any laws or terms of service

Unauthorized access to computer systems is illegal under:
- India: IT Act 2000, Section 43, 66
- International: CFAA (US), Computer Misuse Act (UK), etc.
```

## 🚀 Quick Start

### Prerequisites
```bash
Python 3.8+
pip install -r requirements.txt
```

### Usage Modes

#### 🔍 Scan Mode (CLI)
```bash
# Basic scan with all modules
python main.py https://target.com --all

# Specific modules
python main.py https://target.com --sqli --xss -d 2

# Save report
python main.py https://target.com --all --report
```

#### 🌐 Proxy Mode
```bash
# Start MITM proxy
python main.py -m proxy -p 8080

# Then configure browser:
# Proxy: 127.0.0.1:8080
# Install mitmproxy CA cert for HTTPS
```

#### 🖥️ GUI Mode
```bash
python main.py -m gui
# Or directly:
python -m ui.gui
```

## 📁 Project Structure
```
sayan-sec-tool/
├── core/           # Core engine modules
├── modules/        # Vulnerability detection plugins
├── ui/             # User interface (Tkinter)
├── config.py       # Global configuration
├── main.py         # Entry point
└── requirements.txt
```

## 🧩 Features

### 🔐 Security Modules
| Module | Description | Severity Levels |
|--------|-------------|----------------|
| `sqli_detector` | Error/Time/Union-based SQLi detection | HIGH, CRITICAL |
| `xss_detector` | Reflected/DOM-based XSS detection | MEDIUM, HIGH |
| `info_leak` | Sensitive data exposure detection | LOW → CRITICAL |

### 🛠️ Core Capabilities
- 🕷️ Multi-threaded web crawler
- 🔄 Request repeater for manual testing
- 🌐 MITM proxy with traffic analysis
- 📊 JSON report generation
- 🎨 Simple Tkinter GUI

## 🧪 Testing Targets (Safe for Learning)
```bash
# Intentionally vulnerable apps:
http://testphp.vulnweb.com          # Acunetix test site
http://dvwa.local                    # DVWA (install locally)
http://webgoat.local                 # OWASP WebGoat
http://juice-shop.local             # OWASP Juice Shop
```

## 🔧 Development

### Add New Module
1. Create `modules/new_feature.py`
2. Implement `scan(url, session) -> List[Dict]`
3. Return findings with: `type, url, severity, evidence`

### Run Tests
```bash
# Test on local lab
python main.py http://localhost:8000 --all --report

# Check code quality
flake8 . --count --select=E9,F63,F7,F82 --show-source
```

## 📚 Learning Resources
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [CEH v12 Official Curriculum](https://www.eccouncil.org/programs/certified-ethical-hacker-ceh/)

## 🤝 Contributing
Educational contributions welcome! Please:
1. Follow ethical guidelines
2. Add documentation
3. Include test cases
4. Submit via PR

## 📄 License
MIT License - For educational use only. See LICENSE file.

---
> 🎓 Built by **sayan9168** | Cisco CEH | Python Developer  
> 🔐 "With great power comes great responsibility"
# 💀 Sayan Sec Tool

> Advanced Security & Exploit Toolkit 

![GitHub repo size](https://img.shields.io/github/repo-size/sayan9168/sayan-sec-tool)
![GitHub stars](https://img.shields.io/github/stars/sayan9168/sayan-sec-tool?style=social)
![License](https://img.shields.io/badge/License-MIT-red.svg)

## 📌 About
**Sayan Sec Tool** is a powerful custom-built security toolkit designed for advanced penetration testing, vulnerability assessment, and exploit development. Built for hackers, by a hacker.

## 🚀 Features
- 🔥 Advanced exploit generation & payload customization
- 🌐 Network scanning, enumeration & recon
- 🕵️‍♂️ Stealth mode operations & evasion techniques
- ⚡ Fast and automated vulnerability scanning

## 🛠️ Installation
```bash
git clone https://github.com/sayan9168/sayan-sec-tool.git
cd sayan-sec-tool
# Add your installation commands here
```

## 📖 Usage
```bash
# Add your tool's execution commands here
```

## 📞 Contact & Socials
Got questions, want to collaborate, or need a custom exploit? Hit me up!

- 📧 **Email:** [sm6881164@gmail.com](mailto:sm6881164@gmail.com)
- 📸 **Instagram:** [@_sayyyyan](https://instagram.com/_sayyyyan)
- 💻 **GitHub:** [sayan9168](https://github.com/sayan9168)

---
⚠️ **Disclaimer:** *This tool is strictly for educational and authorized penetration testing purposes only. The developer is not responsible for any misuse or illegal activities. Hack responsibly!*
