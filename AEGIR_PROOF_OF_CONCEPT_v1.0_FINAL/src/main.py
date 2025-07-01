import argparse
import asyncio
import json
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
from core.subdomain_enum import enumerate_subdomains
from core.port_scanner import PortScanner
from core.tech_fingerprint import TechFingerprinter
from core.screenshot_capture import ScreenshotCapture
from core.vuln_scanner import VulnerabilityScanner

@dataclass
class ScanResult:
    """Résultat complet d'un scan."""
    subdomain: str
    port: int
    service: str
    status_code: int
    title: str
    technologies: List[str]
    tech_details: List[Dict]
    response_time: float
    headers: Dict[str, str]
    vulnerabilities: List[Dict]
    screenshot_path: str = ""

@dataclass
class ScanSummary:
    """Résumé du scan complet."""
    domain: str
    total_subdomains: int
    subdomains_with_services: int
    total_services: int
    technologies_found: List[str]
    vulnerabilities_found: List[str]
    screenshots_taken: int
    scan_duration: float
    errors: List[str]

class AegirScanner:
    """Orchestrateur principal pour le scan offensif."""
    
    def __init__(self, domain: str, output_prefix: str = "aegir_report"):
        """
        Initialise le scanner Aegir.
        
        Args:
            domain: Domaine cible
            output_prefix: Préfixe pour les fichiers de sortie
        """
        self.domain = domain
        self.output_prefix = output_prefix
        self.port_scanner = PortScanner()
        self.tech_fingerprinter = TechFingerprinter()
        self.screenshot_capture = ScreenshotCapture(f"{output_prefix}_screenshots")
        self.vuln_scanner = VulnerabilityScanner()
        self.web_ports = [80, 443, 8080, 8443, 3000, 4000, 5000, 8000, 9000]
        self.results = []
        self.errors = []
    
    async def scan_domain(self) -> ScanSummary:
        """
        Exécute le scan complet du domaine.
        
        Returns:
            ScanSummary: Résumé du scan
        """
        start_time = asyncio.get_event_loop().time()
        
        try:
            # 1. Énumération des sous-domaines
            subdomains = enumerate_subdomains(self.domain)
            
            # 2. Scan des ports pour chaque sous-domaine
            for subdomain in subdomains:
                try:
                    port_results = await self.port_scanner.scan_host_ports(subdomain, self.web_ports)
                    
                    # 3. Fingerprinting pour chaque port ouvert
                    for port, port_result in port_results.items():
                        if port_result.is_open:
                            url = f"https://{subdomain}:{port}" if port in [443, 8443] else f"http://{subdomain}:{port}"
                            
                            try:
                                techs = await self.tech_fingerprinter.fingerprint_url(url)
                                vulns = await self.vuln_scanner.scan_url(url)
                                
                                # Capture d'écran
                                screenshot_result = await self.screenshot_capture.capture_single_url(url)
                                
                                scan_result = ScanResult(
                                    subdomain=subdomain,
                                    port=port,
                                    service=port_result.service,
                                    status_code=port_result.status_code,
                                    title=port_result.title,
                                    technologies=[tech.name for tech in techs],
                                    tech_details=[asdict(tech) for tech in techs],
                                    response_time=port_result.response_time,
                                    headers=port_result.headers,
                                    vulnerabilities=[asdict(vuln) for vuln in vulns],
                                    screenshot_path=screenshot_result.screenshot_path if screenshot_result.success else ""
                                )
                                self.results.append(scan_result)
                                
                            except Exception as e:
                                self.errors.append(f"Analysis error for {url}: {str(e)}")
                                
                except Exception as e:
                    self.errors.append(f"Port scan error for {subdomain}: {str(e)}")
            
            end_time = asyncio.get_event_loop().time()
            scan_duration = end_time - start_time
            
            # Créer le résumé
            all_technologies = []
            all_vulnerabilities = []
            screenshots_taken = 0
            
            for result in self.results:
                all_technologies.extend(result.technologies)
                all_vulnerabilities.extend([vuln['name'] for vuln in result.vulnerabilities])
                if result.screenshot_path:
                    screenshots_taken += 1
            
            summary = ScanSummary(
                domain=self.domain,
                total_subdomains=len(subdomains),
                subdomains_with_services=len(set(r.subdomain for r in self.results)),
                total_services=len(self.results),
                technologies_found=list(set(all_technologies)),
                vulnerabilities_found=list(set(all_vulnerabilities)),
                screenshots_taken=screenshots_taken,
                scan_duration=scan_duration,
                errors=self.errors
            )
            
            return summary
            
        except Exception as e:
            self.errors.append(f"Critical error: {str(e)}")
            return ScanSummary(
                domain=self.domain,
                total_subdomains=0,
                subdomains_with_services=0,
                total_services=0,
                technologies_found=[],
                vulnerabilities_found=[],
                screenshots_taken=0,
                scan_duration=0,
                errors=self.errors
            )
    
    def export_json(self, summary: ScanSummary) -> str:
        """
        Exporte les résultats en JSON.
        
        Args:
            summary: Résumé du scan
        
        Returns:
            str: Chemin du fichier JSON
        """
        output_data = {
            "summary": asdict(summary),
            "results": [asdict(result) for result in self.results]
        }
        
        json_path = f"{self.output_prefix}.json"
        with open(json_path, 'w') as f:
            json.dump(output_data, f, indent=2)
        
        return json_path
    
    def export_html(self, summary: ScanSummary) -> str:
        """
        Exporte les résultats en HTML.
        
        Args:
            summary: Résumé du scan
        
        Returns:
            str: Chemin du fichier HTML
        """
        html_path = f"{self.output_prefix}.html"
        
        with open(html_path, 'w') as f:
            f.write("<!DOCTYPE html>\n")
            f.write("<html><head><title>Aegir Report</title>")
            f.write("<style>")
            f.write("body { font-family: Arial, sans-serif; margin: 20px; }")
            f.write(".service { border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }")
            f.write(".tech { background: #f0f0f0; padding: 5px; margin: 2px; border-radius: 3px; display: inline-block; }")
            f.write(".summary { background: #f9f9f9; padding: 15px; border-radius: 5px; margin-bottom: 20px; }")
            f.write("</style></head><body>")
            
            f.write(f"<h1>Aegir Offensive Recon Report</h1>")
            f.write(f"<div class='summary'>")
            f.write(f"<h2>Scan Summary</h2>")
            f.write(f"<p><strong>Domain:</strong> {summary.domain}</p>")
            f.write(f"<p><strong>Total Subdomains:</strong> {summary.total_subdomains}</p>")
            f.write(f"<p><strong>Subdomains with Services:</strong> {summary.subdomains_with_services}</p>")
            f.write(f"<p><strong>Total Services:</strong> {summary.total_services}</p>")
            f.write(f"<p><strong>Scan Duration:</strong> {summary.scan_duration:.2f} seconds</p>")
            f.write(f"<p><strong>Technologies Found:</strong> {', '.join(summary.technologies_found)}</p>")
            f.write(f"<p><strong>Vulnerabilities Found:</strong> {', '.join(summary.vulnerabilities_found)}</p>")
            f.write(f"<p><strong>Screenshots Taken:</strong> {summary.screenshots_taken}</p>")
            f.write("</div>")
            
            f.write(f"<h2>Discovered Services ({len(self.results)})</h2>")
            for result in self.results:
                f.write(f"<div class='service'>")
                f.write(f"<h3>{result.subdomain}:{result.port} - {result.service}</h3>")
                f.write(f"<p><strong>Status:</strong> {result.status_code}</p>")
                f.write(f"<p><strong>Title:</strong> {result.title}</p>")
                f.write(f"<p><strong>Response Time:</strong> {result.response_time:.3f}s</p>")
                f.write(f"<p><strong>Technologies:</strong> ")
                for tech in result.technologies:
                    f.write(f"<span class='tech'>{tech}</span> ")
                f.write("</p>")
                
                if result.vulnerabilities:
                    f.write(f"<p><strong>Vulnerabilities:</strong> ")
                    for vuln in result.vulnerabilities:
                        severity_color = {
                            'LOW': '#ffeb3b',
                            'MEDIUM': '#ff9800', 
                            'HIGH': '#f44336',
                            'CRITICAL': '#9c27b0'
                        }.get(vuln['severity'], '#666')
                        f.write(f"<span class='tech' style='background-color: {severity_color}; color: white;'>{vuln['name']} ({vuln['severity']})</span> ")
                    f.write("</p>")
                
                if result.screenshot_path:
                    f.write(f"<p><strong>Screenshot:</strong> <a href='{result.screenshot_path}' target='_blank'>View</a></p>")
                
                f.write("</div>")
            
            if summary.errors:
                f.write(f"<h2>Errors ({len(summary.errors)})</h2>")
                f.write("<ul>")
                for error in summary.errors:
                    f.write(f"<li>{error}</li>")
                f.write("</ul>")
            
            f.write("</body></html>")
        
        return html_path

async def main():
    """
    Orchestrateur principal :
    - Prend un domaine en argument
    - Enumère les sous-domaines
    - Scanne les ports
    - Fingerprint les services web
    - Agrège et exporte les résultats
    """
    parser = argparse.ArgumentParser(description="Aegir Offensive Recon - Orchestrateur Pentest Pro")
    parser.add_argument("domain", help="Domaine à scanner")
    parser.add_argument("--output", default="aegir_report", help="Préfixe du rapport de sortie")
    args = parser.parse_args()

    domain = args.domain
    output_prefix = args.output

    print(f"[+] Starting Aegir scan for {domain}")
    
    scanner = AegirScanner(domain, output_prefix)
    summary = await scanner.scan_domain()
    
    # Export des résultats
    json_path = scanner.export_json(summary)
    html_path = scanner.export_html(summary)
    
    print(f"[+] Scan completed in {summary.scan_duration:.2f} seconds")
    print(f"[+] Found {summary.total_subdomains} subdomains")
    print(f"[+] Discovered {summary.total_services} web services")
    print(f"[+] Detected {len(summary.technologies_found)} technologies")
    print(f"[+] Found {len(summary.vulnerabilities_found)} vulnerability types")
    print(f"[+] Captured {summary.screenshots_taken} screenshots")
    print(f"[+] JSON report: {json_path}")
    print(f"[+] HTML report: {html_path}")
    print(f"[+] Screenshots directory: {scanner.screenshot_capture.screenshot_dir}")
    
    if summary.errors:
        print(f"[!] {len(summary.errors)} errors occurred during scan")

if __name__ == "__main__":
    asyncio.run(main()) 