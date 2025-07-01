import re
import json
import asyncio
import httpx
from typing import Dict, List, Set, Tuple, Optional
from dataclasses import dataclass
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

@dataclass
class Technology:
    """Technologie détectée."""
    name: str
    category: str
    version: str = ""
    confidence: int = 0
    evidence: List[str] = None
    
    def __post_init__(self):
        if self.evidence is None:
            self.evidence = []

class TechFingerprinter:
    """Fingerprinter technologique professionnel."""
    
    def __init__(self):
        """
        Initialise le fingerprinter technologique.
        """
        # Signatures de technologies organisées par catégorie
        self.tech_signatures = {
            "Web Frameworks": {
                "WordPress": {
                    "headers": ["x-powered-by"],
                    "html": ["wp-content", "wp-includes", "wp-admin", "wp-json"],
                    "js": ["wp-", "jquery"],
                    "confidence": 90
                },
                "Drupal": {
                    "headers": ["x-drupal-cache", "x-generator"],
                    "html": ["drupal", "sites/default", "modules", "themes"],
                    "js": ["Drupal", "drupal"],
                    "confidence": 85
                },
                "Joomla": {
                    "headers": ["x-content-type-options"],
                    "html": ["joomla", "administrator", "components", "modules"],
                    "js": ["Joomla", "joomla"],
                    "confidence": 85
                },
                "Laravel": {
                    "headers": ["x-powered-by"],
                    "html": ["laravel", "storage/logs", "vendor", "artisan"],
                    "js": ["Laravel", "csrf-token"],
                    "confidence": 80
                },
                "Django": {
                    "headers": ["x-powered-by"],
                    "html": ["django", "admin", "static", "media"],
                    "js": ["Django", "csrfmiddlewaretoken"],
                    "confidence": 80
                },
                "Flask": {
                    "headers": ["x-powered-by"],
                    "html": ["flask", "werkzeug", "jinja2"],
                    "js": ["Flask"],
                    "confidence": 75
                },
                "Express.js": {
                    "headers": ["x-powered-by"],
                    "html": ["express", "node_modules"],
                    "js": ["Express", "express"],
                    "confidence": 80
                },
                "React": {
                    "headers": [],
                    "html": ["react", "jsx", "create-react-app"],
                    "js": ["React", "react", "jsx"],
                    "confidence": 85
                },
                "Angular": {
                    "headers": [],
                    "html": ["angular", "ng-", "@angular"],
                    "js": ["Angular", "angular", "ng-"],
                    "confidence": 85
                },
                "Vue.js": {
                    "headers": [],
                    "html": ["vue", "v-", "@vue"],
                    "js": ["Vue", "vue", "v-"],
                    "confidence": 85
                }
            },
            "Web Servers": {
                "Nginx": {
                    "headers": ["server"],
                    "html": [],
                    "js": [],
                    "confidence": 90
                },
                "Apache": {
                    "headers": ["server", "x-powered-by"],
                    "html": ["apache", "mod_"],
                    "js": [],
                    "confidence": 85
                },
                "IIS": {
                    "headers": ["server", "x-aspnet-version"],
                    "html": ["iis", "asp.net"],
                    "js": [],
                    "confidence": 90
                },
                "Caddy": {
                    "headers": ["server"],
                    "html": [],
                    "js": [],
                    "confidence": 85
                }
            },
            "Programming Languages": {
                "PHP": {
                    "headers": ["x-powered-by"],
                    "html": ["php", ".php"],
                    "js": [],
                    "confidence": 80
                },
                "Python": {
                    "headers": ["x-powered-by"],
                    "html": ["python", "wsgi", "asgi"],
                    "js": [],
                    "confidence": 75
                },
                "Node.js": {
                    "headers": ["x-powered-by"],
                    "html": ["node", "express"],
                    "js": ["Node", "node"],
                    "confidence": 80
                },
                "Java": {
                    "headers": ["x-powered-by"],
                    "html": ["java", "jsp", "servlet"],
                    "js": [],
                    "confidence": 75
                },
                "Ruby": {
                    "headers": ["x-powered-by"],
                    "html": ["ruby", "rails"],
                    "js": ["Ruby", "rails"],
                    "confidence": 75
                }
            },
            "Cloud Platforms": {
                "AWS": {
                    "headers": ["x-amz-", "x-amazon-"],
                    "html": ["aws", "amazon", "s3", "ec2"],
                    "js": ["AWS", "aws"],
                    "confidence": 85
                },
                "Azure": {
                    "headers": ["x-azure-", "x-ms-"],
                    "html": ["azure", "microsoft"],
                    "js": ["Azure", "azure"],
                    "confidence": 85
                },
                "Google Cloud": {
                    "headers": ["x-google-"],
                    "html": ["google", "gcp", "cloud.google"],
                    "js": ["Google", "gcp"],
                    "confidence": 85
                },
                "Cloudflare": {
                    "headers": ["cf-ray", "x-cloudflare-"],
                    "html": ["cloudflare"],
                    "js": ["Cloudflare"],
                    "confidence": 90
                }
            },
            "Databases": {
                "MySQL": {
                    "headers": ["x-powered-by"],
                    "html": ["mysql", "mysqli"],
                    "js": ["MySQL"],
                    "confidence": 70
                },
                "PostgreSQL": {
                    "headers": ["x-powered-by"],
                    "html": ["postgresql", "postgres"],
                    "js": ["PostgreSQL"],
                    "confidence": 70
                },
                "MongoDB": {
                    "headers": ["x-powered-by"],
                    "html": ["mongodb", "mongo"],
                    "js": ["MongoDB"],
                    "confidence": 70
                }
            },
            "DevOps Tools": {
                "Docker": {
                    "headers": ["x-docker-"],
                    "html": ["docker", "container"],
                    "js": ["Docker"],
                    "confidence": 80
                },
                "Kubernetes": {
                    "headers": ["x-kubernetes-"],
                    "html": ["kubernetes", "k8s"],
                    "js": ["Kubernetes"],
                    "confidence": 80
                },
                "Jenkins": {
                    "headers": ["x-jenkins-"],
                    "html": ["jenkins"],
                    "js": ["Jenkins"],
                    "confidence": 85
                },
                "GitLab": {
                    "headers": ["x-gitlab-"],
                    "html": ["gitlab"],
                    "js": ["GitLab"],
                    "confidence": 85
                }
            }
        }
    
    def extract_version_from_header(self, header_value: str, tech_name: str) -> str:
        """
        Extrait la version depuis un header.
        
        Args:
            header_value: Valeur du header
            tech_name: Nom de la technologie
        
        Returns:
            str: Version extraite ou chaîne vide
        """
        version_patterns = [
            r'(\d+\.\d+\.\d+)',
            r'(\d+\.\d+)',
            r'(\d+)'
        ]
        
        for pattern in version_patterns:
            match = re.search(pattern, header_value, re.IGNORECASE)
            if match:
                return match.group(1)
        return ""
    
    def analyze_headers(self, headers: Dict[str, str]) -> List[Technology]:
        """
        Analyse les headers HTTP pour détecter les technologies.
        
        Args:
            headers: Dictionnaire des headers HTTP
        
        Returns:
            List[Technology]: Liste des technologies détectées
        """
        detected_techs = []
        
        for category, technologies in self.tech_signatures.items():
            for tech_name, signatures in technologies.items():
                for header_pattern in signatures["headers"]:
                    for header_name, header_value in headers.items():
                        if (header_pattern.lower() in header_name.lower() or 
                            header_pattern.lower() in header_value.lower()):
                            version = self.extract_version_from_header(header_value, tech_name)
                            tech = Technology(
                                name=tech_name,
                                category=category,
                                version=version,
                                confidence=signatures["confidence"],
                                evidence=[f"Header: {header_name}: {header_value}"]
                            )
                            detected_techs.append(tech)
                            break
        
        return detected_techs
    
    def analyze_html_content(self, html_content: str) -> List[Technology]:
        """
        Analyse le contenu HTML pour détecter les technologies.
        
        Args:
            html_content: Contenu HTML de la page
        
        Returns:
            List[Technology]: Liste des technologies détectées
        """
        detected_techs = []
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Analyser le HTML
        html_text = soup.get_text().lower()
        
        # Analyser les scripts
        scripts = soup.find_all('script')
        js_content = ' '.join([script.get_text() for script in scripts if script.get_text()])
        
        for category, technologies in self.tech_signatures.items():
            for tech_name, signatures in technologies.items():
                evidence = []
                
                # Vérifier les signatures HTML
                for html_pattern in signatures["html"]:
                    if html_pattern.lower() in html_text:
                        evidence.append(f"HTML: {html_pattern}")
                
                # Vérifier les signatures JavaScript
                for js_pattern in signatures["js"]:
                    if js_pattern.lower() in js_content.lower():
                        evidence.append(f"JS: {js_pattern}")
                
                # Vérifier les meta tags
                meta_tags = soup.find_all('meta')
                for meta in meta_tags:
                    meta_content = meta.get('content', '').lower()
                    for html_pattern in signatures["html"]:
                        if html_pattern.lower() in meta_content:
                            evidence.append(f"Meta: {html_pattern}")
                
                if evidence:
                    tech = Technology(
                        name=tech_name,
                        category=category,
                        confidence=signatures["confidence"],
                        evidence=evidence
                    )
                    detected_techs.append(tech)
        
        return detected_techs
    
    async def fingerprint_url(self, url: str) -> List[Technology]:
        """
        Détecte les technologies exposées sur une URL.
        
        Args:
            url: URL cible (ex: 'http://example.com')
        
        Returns:
            List[Technology]: Liste des technologies détectées
        """
        detected_techs = []
        
        try:
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
                response = await client.get(url)
                
                # Analyser les headers
                header_techs = self.analyze_headers(dict(response.headers))
                detected_techs.extend(header_techs)
                
                # Analyser le contenu HTML
                if "text/html" in response.headers.get("content-type", ""):
                    html_techs = self.analyze_html_content(response.text)
                    detected_techs.extend(html_techs)
                
        except Exception:
            pass
        
        # Dédupliquer et trier par confiance
        unique_techs = {}
        for tech in detected_techs:
            key = f"{tech.category}:{tech.name}"
            if key not in unique_techs or tech.confidence > unique_techs[key].confidence:
                unique_techs[key] = tech
        
        return sorted(unique_techs.values(), key=lambda x: x.confidence, reverse=True)
    
    async def fingerprint_multiple_urls(self, urls: List[str]) -> Dict[str, List[Technology]]:
        """
        Fingerprint de plusieurs URLs en parallèle.
        
        Args:
            urls: Liste des URLs à analyser
        
        Returns:
            Dict[str, List[Technology]]: Résultats par URL
        """
        semaphore = asyncio.Semaphore(10)  # Limiter la concurrence
        
        async def fingerprint_with_semaphore(url):
            async with semaphore:
                return url, await self.fingerprint_url(url)
        
        tasks = [fingerprint_with_semaphore(url) for url in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        fingerprint_results = {}
        for result in results:
            if isinstance(result, tuple):
                url, techs = result
                fingerprint_results[url] = techs
        
        return fingerprint_results

# Fonction utilitaire
async def quick_fingerprint(url: str) -> List[Technology]:
    """
    Fingerprint rapide d'une URL.
    
    Args:
        url: URL cible
    
    Returns:
        List[Technology]: Liste des technologies détectées
    """
    fingerprinter = TechFingerprinter()
    return await fingerprinter.fingerprint_url(url)

if __name__ == "__main__":
    import sys
    
    async def main():
        if len(sys.argv) < 2:
            print("Usage: python3 tech_fingerprint.py <url>")
            sys.exit(1)
        
        url = sys.argv[1]
        print(f"[+] Fingerprinting {url}...")
        
        techs = await quick_fingerprint(url)
        
        if techs:
            print(f"\n[+] Technologies détectées ({len(techs)}):")
            for tech in techs:
                print(f"  {tech.name} ({tech.category}) - Confiance: {tech.confidence}%")
                if tech.version:
                    print(f"    Version: {tech.version}")
                for evidence in tech.evidence[:3]:  # Afficher les 3 premières preuves
                    print(f"    {evidence}")
                print()
        else:
            print("[-] Aucune technologie détectée")
    
    asyncio.run(main()) 