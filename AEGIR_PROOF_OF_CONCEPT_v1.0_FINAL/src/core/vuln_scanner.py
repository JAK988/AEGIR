import re
import asyncio
import httpx
from typing import Dict, List, Set, Optional, Tuple
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

@dataclass
class Vulnerability:
    """Vulnérabilité détectée."""
    name: str
    category: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    description: str
    evidence: str
    cve_id: str = ""
    cvss_score: float = 0.0
    remediation: str = ""

class VulnerabilityScanner:
    """Scanner de vulnérabilités basé sur les signatures."""
    
    def __init__(self):
        """
        Initialise le scanner de vulnérabilités.
        """
        # Signatures de vulnérabilités organisées par catégorie
        self.vuln_signatures = {
            "Security Headers": {
                "Missing Security Headers": {
                    "description": "Headers de sécurité manquants",
                    "severity": "MEDIUM",
                    "headers_to_check": [
                        "strict-transport-security",
                        "content-security-policy",
                        "x-frame-options",
                        "x-content-type-options",
                        "x-xss-protection",
                        "referrer-policy"
                    ],
                    "cve_id": "",
                    "cvss_score": 4.3,
                    "remediation": "Implémenter les headers de sécurité recommandés"
                },
                "Weak HSTS Configuration": {
                    "description": "Configuration HSTS faible",
                    "severity": "MEDIUM",
                    "pattern": r"max-age=(\d+)",
                    "min_age": 31536000,  # 1 an
                    "cve_id": "",
                    "cvss_score": 4.3,
                    "remediation": "Augmenter max-age à au moins 1 an"
                }
            },
            "Information Disclosure": {
                "Server Information Disclosure": {
                    "description": "Divulgation d'informations serveur",
                    "severity": "LOW",
                    "headers_to_check": ["server", "x-powered-by", "x-aspnet-version"],
                    "cve_id": "",
                    "cvss_score": 2.1,
                    "remediation": "Masquer les informations serveur"
                },
                "Directory Listing": {
                    "description": "Listing de répertoires activé",
                    "severity": "MEDIUM",
                    "indicators": ["Index of /", "Directory listing for"],
                    "cve_id": "",
                    "cvss_score": 4.3,
                    "remediation": "Désactiver le listing de répertoires"
                }
            },
            "Authentication": {
                "Missing Authentication": {
                    "description": "Absence d'authentification",
                    "severity": "HIGH",
                    "indicators": ["admin", "login", "dashboard", "panel"],
                    "cve_id": "",
                    "cvss_score": 7.5,
                    "remediation": "Implémenter une authentification robuste"
                },
                "Weak Authentication": {
                    "description": "Authentification faible",
                    "severity": "MEDIUM",
                    "indicators": ["basic", "digest"],
                    "cve_id": "",
                    "cvss_score": 5.3,
                    "remediation": "Utiliser une authentification forte"
                }
            },
            "Configuration": {
                "Debug Mode Enabled": {
                    "description": "Mode debug activé",
                    "severity": "HIGH",
                    "indicators": ["debug", "development", "trace"],
                    "cve_id": "",
                    "cvss_score": 7.5,
                    "remediation": "Désactiver le mode debug en production"
                },
                "Error Information Disclosure": {
                    "description": "Divulgation d'erreurs détaillées",
                    "severity": "MEDIUM",
                    "indicators": ["stack trace", "error details", "exception"],
                    "cve_id": "",
                    "cvss_score": 4.3,
                    "remediation": "Masquer les détails d'erreurs"
                }
            },
            "TLS/SSL": {
                "Weak Cipher Suites": {
                    "description": "Suites de chiffrement faibles",
                    "severity": "MEDIUM",
                    "cve_id": "",
                    "cvss_score": 4.3,
                    "remediation": "Utiliser des suites de chiffrement fortes"
                },
                "Missing SSL/TLS": {
                    "description": "Absence de chiffrement SSL/TLS",
                    "severity": "HIGH",
                    "cve_id": "",
                    "cvss_score": 7.5,
                    "remediation": "Implémenter HTTPS"
                }
            }
        }
    
    def analyze_security_headers(self, headers: Dict[str, str]) -> List[Vulnerability]:
        """
        Analyse les headers de sécurité.
        
        Args:
            headers: Dictionnaire des headers HTTP
        
        Returns:
            List[Vulnerability]: Liste des vulnérabilités détectées
        """
        vulnerabilities = []
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        # Vérifier les headers manquants
        missing_headers = []
        required_headers = self.vuln_signatures["Security Headers"]["Missing Security Headers"]["headers_to_check"]
        
        for header in required_headers:
            if header not in headers_lower:
                missing_headers.append(header)
        
        if missing_headers:
            vuln = Vulnerability(
                name="Missing Security Headers",
                category="Security Headers",
                severity="MEDIUM",
                description=f"Headers de sécurité manquants: {', '.join(missing_headers)}",
                evidence=f"Headers manquants: {missing_headers}",
                cvss_score=4.3,
                remediation="Implémenter les headers de sécurité recommandés"
            )
            vulnerabilities.append(vuln)
        
        # Vérifier la configuration HSTS
        if "strict-transport-security" in headers_lower:
            hsts_value = headers_lower["strict-transport-security"]
            match = re.search(r"max-age=(\d+)", hsts_value)
            if match:
                max_age = int(match.group(1))
                if max_age < 31536000:  # 1 an
                    vuln = Vulnerability(
                        name="Weak HSTS Configuration",
                        category="Security Headers",
                        severity="MEDIUM",
                        description=f"Configuration HSTS faible (max-age={max_age})",
                        evidence=f"HSTS max-age: {max_age}",
                        cvss_score=4.3,
                        remediation="Augmenter max-age à au moins 1 an"
                    )
                    vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def analyze_information_disclosure(self, headers: Dict[str, str], content: str) -> List[Vulnerability]:
        """
        Analyse la divulgation d'informations.
        
        Args:
            headers: Headers HTTP
            content: Contenu de la page
        
        Returns:
            List[Vulnerability]: Liste des vulnérabilités détectées
        """
        vulnerabilities = []
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        # Vérifier les headers d'information serveur
        info_headers = ["server", "x-powered-by", "x-aspnet-version"]
        disclosed_info = []
        
        for header in info_headers:
            if header in headers_lower:
                disclosed_info.append(f"{header}: {headers_lower[header]}")
        
        if disclosed_info:
            vuln = Vulnerability(
                name="Server Information Disclosure",
                category="Information Disclosure",
                severity="LOW",
                description="Divulgation d'informations serveur",
                evidence=f"Headers divulgués: {', '.join(disclosed_info)}",
                cvss_score=2.1,
                remediation="Masquer les informations serveur"
            )
            vulnerabilities.append(vuln)
        
        # Vérifier le listing de répertoires
        content_lower = content.lower()
        for indicator in ["index of /", "directory listing for"]:
            if indicator in content_lower:
                vuln = Vulnerability(
                    name="Directory Listing",
                    category="Information Disclosure",
                    severity="MEDIUM",
                    description="Listing de répertoires activé",
                    evidence=f"Indicateur trouvé: {indicator}",
                    cvss_score=4.3,
                    remediation="Désactiver le listing de répertoires"
                )
                vulnerabilities.append(vuln)
                break
        
        return vulnerabilities
    
    def analyze_authentication(self, url: str, content: str) -> List[Vulnerability]:
        """
        Analyse les vulnérabilités d'authentification.
        
        Args:
            url: URL analysée
            content: Contenu de la page
        
        Returns:
            List[Vulnerability]: Liste des vulnérabilités détectées
        """
        vulnerabilities = []
        url_lower = url.lower()
        content_lower = content.lower()
        
        # Vérifier les endpoints sensibles sans authentification
        sensitive_paths = ["/admin", "/login", "/dashboard", "/panel", "/manage"]
        for path in sensitive_paths:
            if path in url_lower:
                # Vérifier si la page ne demande pas d'authentification
                auth_indicators = ["login", "password", "username", "authenticate"]
                has_auth = any(indicator in content_lower for indicator in auth_indicators)
                
                if not has_auth:
                    vuln = Vulnerability(
                        name="Missing Authentication",
                        category="Authentication",
                        severity="HIGH",
                        description=f"Endpoint sensible sans authentification: {path}",
                        evidence=f"URL: {url}",
                        cvss_score=7.5,
                        remediation="Implémenter une authentification robuste"
                    )
                    vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def analyze_configuration(self, content: str) -> List[Vulnerability]:
        """
        Analyse les vulnérabilités de configuration.
        
        Args:
            content: Contenu de la page
        
        Returns:
            List[Vulnerability]: Liste des vulnérabilités détectées
        """
        vulnerabilities = []
        content_lower = content.lower()
        
        # Vérifier le mode debug
        debug_indicators = ["debug", "development", "trace"]
        for indicator in debug_indicators:
            if indicator in content_lower:
                vuln = Vulnerability(
                    name="Debug Mode Enabled",
                    category="Configuration",
                    severity="HIGH",
                    description="Mode debug activé",
                    evidence=f"Indicateur trouvé: {indicator}",
                    cvss_score=7.5,
                    remediation="Désactiver le mode debug en production"
                )
                vulnerabilities.append(vuln)
                break
        
        # Vérifier la divulgation d'erreurs
        error_indicators = ["stack trace", "error details", "exception"]
        for indicator in error_indicators:
            if indicator in content_lower:
                vuln = Vulnerability(
                    name="Error Information Disclosure",
                    category="Configuration",
                    severity="MEDIUM",
                    description="Divulgation d'erreurs détaillées",
                    evidence=f"Indicateur trouvé: {indicator}",
                    cvss_score=4.3,
                    remediation="Masquer les détails d'erreurs"
                )
                vulnerabilities.append(vuln)
                break
        
        return vulnerabilities
    
    async def scan_url(self, url: str) -> List[Vulnerability]:
        """
        Scan complet d'une URL pour les vulnérabilités.
        
        Args:
            url: URL à scanner
        
        Returns:
            List[Vulnerability]: Liste des vulnérabilités détectées
        """
        vulnerabilities = []
        
        try:
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
                response = await client.get(url)
                
                # Analyser les headers de sécurité
                header_vulns = self.analyze_security_headers(dict(response.headers))
                vulnerabilities.extend(header_vulns)
                
                # Analyser la divulgation d'informations
                info_vulns = self.analyze_information_disclosure(dict(response.headers), response.text)
                vulnerabilities.extend(info_vulns)
                
                # Analyser l'authentification
                auth_vulns = self.analyze_authentication(url, response.text)
                vulnerabilities.extend(auth_vulns)
                
                # Analyser la configuration
                config_vulns = self.analyze_configuration(response.text)
                vulnerabilities.extend(config_vulns)
                
        except Exception:
            pass
        
        return vulnerabilities
    
    async def scan_multiple_urls(self, urls: List[str]) -> Dict[str, List[Vulnerability]]:
        """
        Scan de vulnérabilités sur plusieurs URLs.
        
        Args:
            urls: Liste des URLs à scanner
        
        Returns:
            Dict[str, List[Vulnerability]]: Résultats par URL
        """
        semaphore = asyncio.Semaphore(10)
        
        async def scan_with_semaphore(url):
            async with semaphore:
                return url, await self.scan_url(url)
        
        tasks = [scan_with_semaphore(url) for url in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        scan_results = {}
        for result in results:
            if isinstance(result, tuple):
                url, vulns = result
                scan_results[url] = vulns
        
        return scan_results

# Fonction utilitaire
async def quick_vuln_scan(url: str) -> List[Vulnerability]:
    """
    Scan rapide de vulnérabilités d'une URL.
    
    Args:
        url: URL à scanner
    
    Returns:
        List[Vulnerability]: Liste des vulnérabilités détectées
    """
    scanner = VulnerabilityScanner()
    return await scanner.scan_url(url) 