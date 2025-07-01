# 🔥 AEGIR - Offensive Reconnaissance Tool

**AEGIR** is a professional, automated offensive reconnaissance tool that combines subdomain enumeration, port scanning, technology fingerprinting, screenshot capture, and vulnerability analysis into a single integrated workflow.

## 🚀 Features

### 🔍 Subdomain Enumeration

* **Multiple sources**: Certificate Transparency (crt.sh), HackerTarget API, DNS brute force
* **Smart deduplication**: CNAME resolution, normalization, duplicate removal
* **Wildcard filtering**: Automatic detection and removal of DNS false positives
* **Configurable wordlist**: 60+ common words + extensible

### 🔌 Port Scanning

* **Asynchronous scanning**: httpx for web ports, socket for other services
* **Service detection**: 30+ common ports mapped (HTTP, HTTPS, SSH, FTP, etc.)
* **Metadata extraction**: HTTP status, title, headers, response time
* **Rate limiting**: Controls network load and respects limits

### 🧬 Technology Fingerprinting

* **Advanced signatures**: HTTP headers, HTML/JS content, meta tags
* **6 categories**: Web Frameworks, Web Servers, Programming Languages, Cloud Platforms, Databases, DevOps Tools
* **Confidence scoring**: 70-90% based on signature reliability
* **Version extraction**: Automatic header parsing

### 📸 Screenshot Capture

* **Headless Playwright**: High-quality capture at 1920x1080
* **User-Agent rotation**: 5 different user-agents to avoid detection
* **Timeout management**: 30s per page with full load wait
* **Smart naming**: Files organized by domain/port

### 🛡️ Vulnerability Analysis

* **Security headers**: HSTS, CSP, X-Frame-Options, etc.
* **Information disclosure**: Server headers, directory listing
* **Authentication**: Unprotected sensitive endpoints
* **Configuration**: Debug mode, detailed errors
* **CVSS scoring**: Automatic risk level evaluation

### 📊 Professional Reports

* **JSON export**: Structured data for integration
* **HTML export**: Visual report with metrics and screenshots
* **CLI summary**: Real-time statistics
* **Correlation**: Link between services, technologies, and vulnerabilities

## 🛠️ Installation

### Requirements

* Python 3.8+
* pip3

### Install dependencies

```bash
# Install Python packages
pip3 install httpx dnspython beautifulsoup4 playwright

# Install Playwright browser
playwright install chromium
```

### Quick install

```bash
git clone <repository>
cd AEGIR
pip3 install -r requirements.txt
playwright install chromium
```

## 📖 Usage

### Basic scan

```bash
python3 main.py example.com
```

### Scan with custom report

```bash
python3 main.py example.com --output my_report
```

### Sample output

```
[+] Starting Aegir scan for example.com
[+] Scan completed in 45.23 seconds
[+] Found 12 subdomains
[+] Discovered 8 web services
[+] Detected 15 technologies
[+] Found 3 vulnerability types
[+] Captured 8 screenshots
[+] JSON report: aegir_report.json
[+] HTML report: aegir_report.html
[+] Screenshots directory: aegir_report_screenshots
```

## 🏗️ Architecture

### Main Modules

```
AEGIR/
├── main.py                 # Main orchestrator
├── subdomain_enum.py       # Subdomain enumeration
├── port_scanner.py         # Port scanning
├── tech_fingerprint.py     # Technology fingerprinting
├── screenshot_capture.py   # Screenshot capture
├── vuln_scanner.py         # Vulnerability analysis
└── README.md               # Documentation
```

### Workflow

1. **Enumeration** → Discover subdomains
2. **Port scan** → Identify active services
3. **Fingerprinting** → Detect technologies
4. **Screenshot capture** → Visual documentation
5. **Vulnerability analysis** → Risk assessment
6. **Aggregation** → Correlate results
7. **Export** → Generate reports

## 📊 Report Examples

### JSON Summary

```json
{
  "summary": {
    "domain": "example.com",
    "total_subdomains": 12,
    "subdomains_with_services": 8,
    "total_services": 15,
    "technologies_found": ["Nginx", "WordPress", "PHP", "MySQL"],
    "vulnerabilities_found": ["Missing Security Headers", "Server Information Disclosure"],
    "screenshots_taken": 8,
    "scan_duration": 45.23
  }
}
```

### HTML Report

* **Executive summary** with key metrics
* **Discovered services** with technologies and vulnerabilities
* **Embedded screenshots** for visual documentation
* **Color coding** for vulnerability severity levels

## 🔧 Advanced Configuration

### Customizing ports

```python
# In main.py
self.web_ports = [80, 443, 8080, 8443, 3000, 4000, 5000, 8000, 9000]
```

### Adding technology signatures

```python
# In tech_fingerprint.py
"New Framework": {
    "headers": ["x-powered-by"],
    "html": ["new-framework"],
    "js": ["NewFramework"],
    "confidence": 85
}
```

### Custom vulnerability configuration

```python
# In vuln_scanner.py
"Custom Vulnerability": {
    "description": "Custom description",
    "severity": "HIGH",
    "indicators": ["custom-indicator"],
    "cvss_score": 7.5
}
```

## 🎯 Use Cases

### External Pentest

```bash
# Full scan of a target domain
python3 main.py target-company.com --output pentest_report
```

### Bug Bounty

```bash
# Quick scan for attack surface identification
python3 main.py bugbounty-target.com
```

### Security Audit

```bash
# Complete documentation for audit report
python3 main.py audit-domain.com --output security_audit
```

## ⚡ Performance

### Optimizations

* **Asynchronous scan**: Parallelized requests
* **Rate limiting**: Bandwidth-aware scanning
* **DNS cache**: Reuses resolutions
* **Timeouts**: Handles slow services

### Typical metrics

* **100 subdomains**: \~2-3 minutes
* **50 web services**: \~1-2 minutes
* **Screenshot capture**: \~30s per page
* **Vulnerability analysis**: \~5s per service

## 🔒 Security & Ethics

### Best practices

* **Authorization**: Always obtain written permission
* **Rate limiting**: Respect service limits
* **Logs**: Document all activity
* **Reports**: Classify sensitive information

### Limitations

* **Scope**: Stay within the defined scope
* **Impact**: Avoid destructive testing
* **Legality**: Comply with local laws

## 🤝 Contribution

### Development

1. Fork the project
2. Create a feature branch
3. Implement improvements
4. Test thoroughly
5. Submit a pull request

### Desired Improvements

* [ ] Nuclei integration
* [ ] Advanced SSL/TLS scanning
* [ ] WAF detection
* [ ] REST API
* [ ] Web interface
* [ ] CI/CD integration

## 📄 License

This project is licensed under the MIT License. See the `LICENSE` file for details.

## ⚠️ Disclaimer

**AEGIR is a penetration testing tool. Its use must be strictly limited to authorized environments. The authors are not responsible for any misuse of this tool.**

## 📞 Support

* **Issues**: GitHub Issues
* **Documentation**: README.md
* **Examples**: `examples/` folder

---

**AEGIR** - Professional offensive reconnaissance tool 🔥

## 👏 Credits

Developed and orchestrated by **Antoine Kojfer (JAK) Disconnect**

---

## 📝 Version Notes and Roadmap

### Version 1.0 — Advanced Proof of Concept

* Modular architecture, complete pipeline, externalized configuration, structured logging, reusable self-tests.
* Developed by Antoine Kojfer (JAK) - Senior Security Researcher
* Status: Advanced proof of concept, ready for evaluation, not production-ready.

### Development Roadmap

* **v1.1**: Robustness testing, advanced vulnerabilities, error handling
* **v1.2**: Performance, REST API, monitoring
* **v2.0**: Wordlists, advanced reporting, advanced configuration
* **v2.1+**: User interface, AI integration, collaboration
