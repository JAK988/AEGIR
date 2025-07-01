# 🔥 AEGIR - Smart Offensive Reconnaissance Platform

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Proof%20of%20Concept-orange.svg)](README.md)
[![Author](https://img.shields.io/badge/Author-Antoine%20Kojfer-blue.svg)](README.md)

> **Professional offensive reconnaissance tool combining subdomain enumeration, port scanning, technology fingerprinting, vulnerability analysis, and automated screenshot capture in a unified workflow.**

## 🚀 Features

### 🔍 **Smart Enumeration**
- **Multi-source discovery**: Certificate Transparency, DNS brute force, search engines, HackerTarget API
- **Intelligent scoring**: Cross-validation, confidence weighting, source correlation
- **Wildcard filtering**: Automatic false positive elimination
- **Plugin architecture**: Extensible enumeration sources

### 🔌 **Advanced Port Scanning**
- **Async scanning**: High-performance concurrent port detection
- **Service fingerprinting**: 30+ common services mapped
- **Metadata extraction**: HTTP status, headers, response times
- **Rate limiting**: Network-friendly scanning

### 🧬 **Technology Fingerprinting**
- **6 categories**: Web Frameworks, Servers, Languages, Cloud, Databases, DevOps
- **Advanced signatures**: Headers, HTML/JS content, meta tags
- **Confidence scoring**: 70-90% accuracy based on signature reliability
- **Version detection**: Automatic version parsing

### 📸 **Automated Screenshots**
- **Playwright headless**: High-quality 1920x1080 captures
- **User-Agent rotation**: 5 different agents to avoid detection
- **Smart timeouts**: 30s per page with complete load waiting
- **Intelligent naming**: Organized by domain/port

### 🛡️ **Vulnerability Analysis**
- **Security headers**: HSTS, CSP, X-Frame-Options, etc.
- **Information disclosure**: Server headers, directory listing
- **Authentication bypass**: Unprotected sensitive endpoints
- **Configuration issues**: Debug mode, detailed errors
- **CVSS scoring**: Automatic risk assessment

### 📊 **Professional Reporting**
- **JSON export**: Structured data for integration
- **HTML reports**: Visual reports with metrics and screenshots
- **CLI summary**: Real-time statistics
- **Correlation**: Service → Technology → Vulnerability mapping

## 🏗️ Architecture

```
AEGIR/
├── src/core/           # Core modules (enumeration, scanning, fingerprinting)
├── src/utils/          # Utilities and helpers
├── config/             # Externalized configuration
├── docs/               # Technical documentation
├── smart_main.py       # Main orchestrator
└── requirements.txt    # Dependencies
```

## 🛠️ Quick Start

```bash
# Installation
git clone https://github.com/your-username/aegir.git
cd aegir
pip install -r requirements.txt
playwright install chromium

# Basic scan
python smart_main.py example.com

# Advanced scan with custom output
python smart_main.py target.com --confidence-level strict --output pentest_report
```

## 📈 Performance

- **100 subdomains**: ~2-3 minutes
- **50 web services**: ~1-2 minutes  
- **Screenshot capture**: ~30s per page
- **Vulnerability analysis**: ~5s per service

## 🎯 Use Cases

- **External Pentesting**: Complete reconnaissance workflow
- **Bug Bounty**: Attack surface discovery
- **Security Audits**: Comprehensive documentation
- **Asset Inventory**: Technology stack mapping

## 🔒 Security & Ethics

- **Authorization required**: Always obtain written permission
- **Rate limiting**: Respect service limits
- **Legal compliance**: Follow local laws and regulations
- **Ethical usage**: Professional pentesting only

## 👨‍💻 Author

**Developed by Antoine Kojfer (JAK)**
- Senior Security Researcher
- Offensive Security Specialist
- Creator of AEGIR Platform

## 📋 Roadmap

- **v1.1**: Robustness tests, advanced vulnerabilities, error handling
- **v1.2**: Performance optimization, REST API, monitoring
- **v2.0**: Enhanced wordlists, advanced reporting, configuration
- **v2.1+**: Web interface, AI integration, collaboration features

## 🤝 Contributing

1. Fork the project
2. Create a feature branch
3. Implement improvements
4. Test thoroughly
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

**AEGIR is a penetration testing tool. Usage must be strictly limited to authorized environments. The authors are not responsible for misuse of this tool.**

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/your-username/aegir/issues)
- **Documentation**: [Technical Architecture](docs/TECHNICAL_ARCHITECTURE.md)
- **Examples**: Check the `examples/` directory

---

**AEGIR** - Professional Offensive Reconnaissance Platform 🔥

*Built with ❤️ by the security community* 