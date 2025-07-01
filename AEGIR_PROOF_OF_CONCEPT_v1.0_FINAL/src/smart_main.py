#!/usr/bin/env python3
"""
Aegir Smart Recon - Orchestrateur Pentest Intelligent
Version 2.0 - Architecture refactorisée avec validation croisée et PoC automatiques

Auteur: Antoine Kojfer (JAK) Disconnect
"""

import argparse
import asyncio
import json
import os
from pathlib import Path
from typing import Dict, List
from dataclasses import dataclass, asdict
from core.smart_recon import SmartRecon, ValidatedTarget, ExploitableVuln

@dataclass
class SmartScanResult:
    """Résultat du scan intelligent."""
    domain: str
    validated_targets: List[ValidatedTarget]
    exploitable_vulns: List[ExploitableVuln]
    scan_duration: float
    total_subdomains_found: int
    total_targets_validated: int
    total_vulns_exploitable: int
    poc_scripts_generated: int

class SmartAegirScanner:
    """Orchestrateur intelligent pour le scan offensif."""
    
    def __init__(self, domain: str, output_prefix: str = "smart_aegir_report"):
        """
        Initialise le scanner intelligent Aegir.
        
        Args:
            domain: Domaine cible
            output_prefix: Préfixe pour les fichiers de sortie
        """
        self.domain = domain
        self.output_prefix = output_prefix
        self.smart_recon = SmartRecon(max_concurrent=50, timeout=10.0)
        self.results = []
        self.errors = []
    
    async def smart_scan_domain(self) -> SmartScanResult:
        """
        Exécute le scan intelligent du domaine.
        
        Returns:
            SmartScanResult: Résultat du scan intelligent
        """
        start_time = asyncio.get_event_loop().time()
        
        try:
            print(f"[+] Starting SMART Aegir scan for {self.domain}")
            print(f"[+] Phase 1: Stealth enumeration")
            
            # 1. Énumération silencieuse
            subdomains = await self.smart_recon.stealth_enum(self.domain)
            
            print(f"[+] Phase 2: Cross-validation")
            
            # 2. Validation croisée des cibles
            validated_targets = await self.smart_recon.validate_targets(subdomains)
            
            print(f"[+] Phase 3: Exploitable vulnerability scanning")
            
            # 3. Scan des vulnérabilités exploitables uniquement
            exploitable_vulns = await self.smart_recon.scan_exploitable_vulns(validated_targets)
            
            # 4. Génération des PoC scripts
            poc_scripts = self.generate_poc_scripts(exploitable_vulns)
            
            end_time = asyncio.get_event_loop().time()
            scan_duration = end_time - start_time
            
            result = SmartScanResult(
                domain=self.domain,
                validated_targets=validated_targets,
                exploitable_vulns=exploitable_vulns,
                scan_duration=scan_duration,
                total_subdomains_found=len(subdomains),
                total_targets_validated=len(validated_targets),
                total_vulns_exploitable=len(exploitable_vulns),
                poc_scripts_generated=len(poc_scripts)
            )
            
            return result
            
        except Exception as e:
            self.errors.append(f"Critical error: {str(e)}")
            return SmartScanResult(
                domain=self.domain,
                validated_targets=[],
                exploitable_vulns=[],
                scan_duration=0,
                total_subdomains_found=0,
                total_targets_validated=0,
                total_vulns_exploitable=0,
                poc_scripts_generated=0
            )
    
    def generate_poc_scripts(self, vulns: List[ExploitableVuln]) -> List[str]:
        """Génère les scripts PoC pour les vulnérabilités exploitables."""
        poc_scripts = []
        
        # Créer le dossier exploits
        exploits_dir = f"{self.output_prefix}_exploits"
        os.makedirs(exploits_dir, exist_ok=True)
        
        for i, vuln in enumerate(vulns):
            # Générer un nom de fichier sécurisé
            safe_name = vuln.name.lower().replace(' ', '_').replace('(', '').replace(')', '')
            safe_target = vuln.target.replace('.', '_').replace(':', '_')
            filename = f"{safe_name}_{safe_target}_{i+1}.py"
            filepath = os.path.join(exploits_dir, filename)
            
            # Écrire le script PoC
            with open(filepath, 'w') as f:
                f.write(vuln.poc_script)
            
            poc_scripts.append(filepath)
        
        return poc_scripts
    
    def export_json(self, result: SmartScanResult) -> str:
        """
        Exporte les résultats en JSON.
        
        Args:
            result: Résultat du scan intelligent
        
        Returns:
            str: Chemin du fichier JSON
        """
        output_data = {
            "scan_info": {
                "domain": result.domain,
                "scan_duration": result.scan_duration,
                "total_subdomains_found": result.total_subdomains_found,
                "total_targets_validated": result.total_targets_validated,
                "total_vulns_exploitable": result.total_vulns_exploitable,
                "poc_scripts_generated": result.poc_scripts_generated
            },
            "validated_targets": [asdict(target) for target in result.validated_targets],
            "exploitable_vulnerabilities": [asdict(vuln) for vuln in result.exploitable_vulns]
        }
        
        json_path = f"{self.output_prefix}.json"
        with open(json_path, 'w') as f:
            json.dump(output_data, f, indent=2)
        
        return json_path
    
    def export_html(self, result: SmartScanResult) -> str:
        """
        Exporte les résultats en HTML.
        
        Args:
            result: Résultat du scan intelligent
        
        Returns:
            str: Chemin du fichier HTML
        """
        html_path = f"{self.output_prefix}.html"
        
        with open(html_path, 'w') as f:
            f.write("<!DOCTYPE html>\n")
            f.write("<html><head><title>Smart Aegir Report</title>")
            f.write("<style>")
            f.write("body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background: #f5f5f5; }")
            f.write(".container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }")
            f.write(".header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }")
            f.write(".summary { background: #f8f9fa; padding: 20px; border-radius: 8px; margin-bottom: 20px; border-left: 4px solid #007bff; }")
            f.write(".target { border: 1px solid #e9ecef; margin: 15px 0; padding: 15px; border-radius: 8px; background: white; }")
            f.write(".vuln { border: 1px solid #dc3545; margin: 10px 0; padding: 15px; border-radius: 8px; background: #fff5f5; }")
            f.write(".tech { background: #e3f2fd; padding: 5px 10px; margin: 2px; border-radius: 15px; display: inline-block; font-size: 12px; }")
            f.write(".severity-high { background: #ffebee; color: #c62828; border: 1px solid #ffcdd2; }")
            f.write(".severity-medium { background: #fff3e0; color: #ef6c00; border: 1px solid #ffcc02; }")
            f.write(".severity-low { background: #f1f8e9; color: #33691e; border: 1px solid #c5e1a5; }")
            f.write(".poc-link { background: #007bff; color: white; padding: 5px 10px; text-decoration: none; border-radius: 5px; display: inline-block; margin: 5px; }")
            f.write(".poc-link:hover { background: #0056b3; }")
            f.write("</style></head><body>")
            
            f.write(f"<div class='container'>")
            f.write(f"<div class='header'>")
            f.write(f"<h1>🔍 Smart Aegir Offensive Recon Report</h1>")
            f.write(f"<p>Intelligent reconnaissance with cross-validation and automated PoC generation</p>")
            f.write(f"</div>")
            
            f.write(f"<div class='summary'>")
            f.write(f"<h2>📊 Scan Summary</h2>")
            f.write(f"<p><strong>Target Domain:</strong> {result.domain}</p>")
            f.write(f"<p><strong>Scan Duration:</strong> {result.scan_duration:.2f} seconds</p>")
            f.write(f"<p><strong>Subdomains Found:</strong> {result.total_subdomains_found}</p>")
            f.write(f"<p><strong>Validated Targets:</strong> {result.total_targets_validated}</p>")
            f.write(f"<p><strong>Exploitable Vulnerabilities:</strong> {result.total_vulns_exploitable}</p>")
            f.write(f"<p><strong>PoC Scripts Generated:</strong> {result.poc_scripts_generated}</p>")
            f.write("</div>")
            
            if result.validated_targets:
                f.write(f"<h2>🎯 Validated Targets ({len(result.validated_targets)})</h2>")
                for target in result.validated_targets:
                    f.write(f"<div class='target'>")
                    f.write(f"<h3>🔗 {target.subdomain}</h3>")
                    f.write(f"<p><strong>IP:</strong> {target.ip}</p>")
                    f.write(f"<p><strong>Service Type:</strong> {target.service_type}</p>")
                    f.write(f"<p><strong>Validation Score:</strong> {target.validation_score:.2f}</p>")
                    f.write(f"<p><strong>Response Time:</strong> {target.response_time:.3f}s</p>")
                    f.write(f"<p><strong>Confidence Sources:</strong> ")
                    for source in target.confidence_sources:
                        f.write(f"<span class='tech'>{source}</span> ")
                    f.write("</p>")
                    f.write("</div>")
            
            if result.exploitable_vulns:
                f.write(f"<h2>💥 Exploitable Vulnerabilities ({len(result.exploitable_vulns)})</h2>")
                for vuln in result.exploitable_vulns:
                    severity_class = f"severity-{vuln.severity.lower()}"
                    f.write(f"<div class='vuln {severity_class}'>")
                    f.write(f"<h3>🚨 {vuln.name}</h3>")
                    f.write(f"<p><strong>Target:</strong> {vuln.target}</p>")
                    f.write(f"<p><strong>Severity:</strong> {vuln.severity}</p>")
                    f.write(f"<p><strong>Exploitability:</strong> {vuln.exploitability}</p>")
                    f.write(f"<p><strong>CVSS Score:</strong> {vuln.cvss_score}</p>")
                    f.write(f"<p><strong>Description:</strong> {vuln.description}</p>")
                    
                    # Lien vers le PoC
                    safe_name = vuln.name.lower().replace(' ', '_').replace('(', '').replace(')', '')
                    safe_target = vuln.target.replace('.', '_').replace(':', '_')
                    poc_filename = f"{safe_name}_{safe_target}.py"
                    poc_path = f"{self.output_prefix}_exploits/{poc_filename}"
                    f.write(f"<p><strong>PoC Script:</strong> <a href='{poc_path}' class='poc-link' target='_blank'>📜 View Exploit Script</a></p>")
                    
                    f.write("</div>")
            
            if result.poc_scripts_generated > 0:
                f.write(f"<h2>⚡ Generated Exploit Scripts</h2>")
                f.write(f"<p>✅ {result.poc_scripts_generated} exploit scripts have been generated in the <code>{self.output_prefix}_exploits/</code> directory.</p>")
                f.write(f"<p>🚀 These scripts are ready to use for exploitation and proof-of-concept demonstrations.</p>")
            
            f.write("</div>")
            f.write("</body></html>")
        
        return html_path
    
    def print_cli_summary(self, result: SmartScanResult):
        """Affiche un résumé CLI du scan."""
        print("\n" + "="*60)
        print("🔍 SMART AEGIR SCAN COMPLETED")
        print("="*60)
        print(f"🎯 Target: {result.domain}")
        print(f"⏱️  Duration: {result.scan_duration:.2f} seconds")
        print(f"📊 Subdomains Found: {result.total_subdomains_found}")
        print(f"✅ Validated Targets: {result.total_targets_validated}")
        print(f"💥 Exploitable Vulnerabilities: {result.total_vulns_exploitable}")
        print(f"⚡ PoC Scripts Generated: {result.poc_scripts_generated}")
        
        if result.validated_targets:
            print(f"\n🎯 VALIDATED TARGETS:")
            for target in result.validated_targets:
                print(f"  • {target.subdomain} ({target.service_type}) - Score: {target.validation_score:.2f}")
        
        if result.exploitable_vulns:
            print(f"\n💥 EXPLOITABLE VULNERABILITIES:")
            for vuln in result.exploitable_vulns:
                print(f"  • {vuln.name} on {vuln.target} - {vuln.severity} (CVSS: {vuln.cvss_score})")
        
        if result.poc_scripts_generated > 0:
            print(f"\n⚡ EXPLOIT SCRIPTS:")
            print(f"  📁 Check the '{self.output_prefix}_exploits/' directory for ready-to-use PoC scripts")
        
        print("\n" + "="*60)

async def main():
    """Fonction principale."""
    parser = argparse.ArgumentParser(
        description="Smart Aegir Offensive Recon - Intelligent reconnaissance with cross-validation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 smart_main.py example.com
  python3 smart_main.py target.com --output my_scan
        """
    )
    
    parser.add_argument("domain", help="Target domain to scan")
    parser.add_argument("--output", default="smart_aegir_report", 
                       help="Output file prefix (default: smart_aegir_report)")
    
    args = parser.parse_args()
    
    # Initialiser le scanner intelligent
    scanner = SmartAegirScanner(args.domain, args.output)
    
    # Exécuter le scan
    result = await scanner.smart_scan_domain()
    
    # Exporter les résultats
    json_path = scanner.export_json(result)
    html_path = scanner.export_html(result)
    
    # Afficher le résumé CLI
    scanner.print_cli_summary(result)
    
    print(f"\n📄 Reports generated:")
    print(f"  • JSON: {json_path}")
    print(f"  • HTML: {html_path}")
    if result.poc_scripts_generated > 0:
        print(f"  • Exploits: {args.output}_exploits/")

if __name__ == "__main__":
    asyncio.run(main()) 