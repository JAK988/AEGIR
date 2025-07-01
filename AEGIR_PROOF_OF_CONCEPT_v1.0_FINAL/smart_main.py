#!/usr/bin/env python3
"""
Aegir - Smart Reconnaissance Platform
Main orchestrator avec architecture plugin et scoring intelligent
"""

import asyncio
import argparse
import json
import time
from pathlib import Path
from typing import List, Dict

# Import des modules core
from src.core.enumeration_engine import EnumerationEngine
from src.core.port_scanner import PortScanner
from src.core.tech_fingerprint import TechFingerprinter
from src.core.vuln_scanner import VulnerabilityScanner
from src.core.screenshot_capture import ScreenshotCapture
from src.utils.report_generator import ReportGenerator

class SmartReconOrchestrator:
    """Orchestrateur intelligent pour la reconnaissance offensive."""
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.enumeration_engine = EnumerationEngine(self.config.get('enumeration', {}))
        self.port_scanner = PortScanner()
        self.tech_fingerprinter = TechFingerprinter()
        self.vuln_scanner = VulnerabilityScanner()
        self.screenshot_capture = ScreenshotCapture()
        self.report_generator = ReportGenerator()
        
        # Résultats globaux
        self.results = {
            'enumeration': {},
            'port_scan': {},
            'tech_fingerprint': {},
            'vulnerability_scan': {},
            'screenshots': {},
            'summary': {}
        }
    
    async def run_full_reconnaissance(self, domain: str, output_dir: str = "reports") -> Dict:
        """Exécute une reconnaissance complète et intelligente."""
        start_time = time.time()
        
        print("🚀 AEGIR SMART RECON - Starting Intelligent Reconnaissance")
        print("="*70)
        print(f"🎯 Target: {domain}")
        print(f"📁 Output: {output_dir}")
        print("="*70)
        
        try:
            # 1. ÉNUMÉRATION INTELLIGENTE
            print("\n🔍 PHASE 1: INTELLIGENT ENUMERATION")
            print("-" * 50)
            
            enum_results = await self.enumeration_engine.enumerate_domain(domain)
            self.results['enumeration'] = enum_results
            
            # Affichage du résumé d'énumération
            self.enumeration_engine.print_summary()
            
            if not enum_results.get('subdomains', []):
                print("[!] No subdomains found. Stopping reconnaissance.")
                return self.results
            
            # 2. SCAN DE PORTS PARALLÈLE
            print(f"\n🔌 PHASE 2: PARALLEL PORT SCANNING")
            print("-" * 50)
            print(f"[+] Scanning {len(enum_results['subdomains'])} subdomains...")
            
            port_results = await self._scan_all_ports(enum_results['subdomains'])
            self.results['port_scan'] = port_results
            
            # 3. FINGERPRINTING TECHNOLOGIQUE
            print(f"\n🔬 PHASE 3: TECHNOLOGY FINGERPRINTING")
            print("-" * 50)
            
            tech_results = await self._fingerprint_all_targets(port_results)
            self.results['tech_fingerprint'] = tech_results
            
            # 4. SCAN DE VULNÉRABILITÉS
            print(f"\n🛡️  PHASE 4: VULNERABILITY SCANNING")
            print("-" * 50)
            
            vuln_results = await self._scan_vulnerabilities(tech_results)
            self.results['vulnerability_scan'] = vuln_results
            
            # 5. CAPTURE D'ÉCRANS
            print(f"\n📸 PHASE 5: SCREENSHOT CAPTURE")
            print("-" * 50)
            
            screenshot_results = await self._capture_screenshots(port_results)
            self.results['screenshots'] = screenshot_results
            
            # 6. GÉNÉRATION DE RAPPORTS
            print(f"\n📊 PHASE 6: REPORT GENERATION")
            print("-" * 50)
            
            end_time = time.time()
            self.results['summary'] = {
                'target_domain': domain,
                'total_duration': end_time - start_time,
                'subdomains_found': len(enum_results.get('subdomains', [])),
                'targets_scanned': len(port_results),
                'vulnerabilities_found': len(vuln_results.get('vulnerabilities', [])),
                'screenshots_captured': len(screenshot_results)
            }
            
            # Génération des rapports
            await self._generate_reports(output_dir)
            
            # Affichage du résumé final
            self._print_final_summary()
            
            return self.results
            
        except Exception as e:
            print(f"\n[!] CRITICAL ERROR: {e}")
            print("[!] Attempting to save partial results...")
            
            # Sauvegarde des résultats partiels
            try:
                end_time = time.time()
                self.results['summary'] = {
                    'target_domain': domain,
                    'total_duration': end_time - start_time,
                    'error': str(e),
                    'partial_results': True
                }
                await self._generate_reports(output_dir)
            except Exception as save_error:
                print(f"[!] Failed to save partial results: {save_error}")
            
            raise
    
    async def _safe_enumeration(self, domain: str) -> Dict:
        """Énumération avec gestion d'erreurs robuste."""
        try:
            return await self.enumeration_engine.enumerate_domain(domain)
        except Exception as e:
            print(f"[!] Enumeration failed: {e}")
            return {'subdomains': [], 'error': str(e)}
    
    async def _safe_port_scan(self, subdomains: List[str]) -> Dict:
        """Port scan avec gestion d'erreurs robuste."""
        try:
            return await self._scan_all_ports(subdomains)
        except Exception as e:
            print(f"[!] Port scan failed: {e}")
            return {}
    
    async def _safe_tech_fingerprint(self, port_results: Dict) -> Dict:
        """Tech fingerprinting avec gestion d'erreurs robuste."""
        try:
            return await self._fingerprint_all_targets(port_results)
        except Exception as e:
            print(f"[!] Tech fingerprinting failed: {e}")
            return {}
    
    async def _safe_vuln_scan(self, tech_results: Dict) -> Dict:
        """Vuln scan avec gestion d'erreurs robuste."""
        try:
            return await self._scan_vulnerabilities(tech_results)
        except Exception as e:
            print(f"[!] Vulnerability scan failed: {e}")
            return {'vulnerabilities': [], 'error': str(e)}
    
    async def _safe_screenshot_capture(self, port_results: Dict) -> Dict:
        """Screenshot capture avec gestion d'erreurs robuste."""
        try:
            return await self._capture_screenshots(port_results)
        except Exception as e:
            print(f"[!] Screenshot capture failed: {e}")
            return {}
    
    async def _safe_generate_reports(self, output_dir: str):
        """Génération de rapports avec gestion d'erreurs robuste."""
        try:
            await self._generate_reports(output_dir)
        except Exception as e:
            print(f"[!] Report generation failed: {e}")
            # Fallback: sauvegarde JSON basique
            try:
                Path(output_dir).mkdir(exist_ok=True)
                timestamp = int(time.time())
                json_path = f"{output_dir}/fallback_report_{timestamp}.json"
                with open(json_path, 'w') as f:
                    json.dump(self._make_json_serializable(self.results), f, indent=2, default=str)
                print(f"[+] Fallback report saved: {json_path}")
            except Exception as fallback_error:
                print(f"[!] Fallback report failed: {fallback_error}")
    
    async def _scan_all_ports(self, subdomains: List[str]) -> Dict:
        """Scan de ports parallèle pour tous les sous-domaines."""
        results = {}
        
        # Scan parallèle avec limitation de concurrence
        semaphore = asyncio.Semaphore(10)  # Max 10 scans simultanés
        
        async def scan_single_target(subdomain: str) -> tuple:
            async with semaphore:
                try:
                    port_results = await self.port_scanner.scan_host_ports(subdomain)
                    open_ports = [port for port, result in port_results.items() if result.is_open]
                    return (subdomain, open_ports)
                except Exception as e:
                    print(f"[!] Port scan failed for {subdomain}: {e}")
                    return (subdomain, [])
        
        # Exécution parallèle
        tasks = [scan_single_target(subdomain) for subdomain in subdomains]
        scan_results = await asyncio.gather(*tasks)
        
        # Agrégation des résultats
        for subdomain, ports in scan_results:
            if ports:
                results[subdomain] = ports
                print(f"[+] {subdomain}: {len(ports)} open ports")
        
        return results
    
    async def _fingerprint_all_targets(self, port_results: Dict) -> Dict:
        """Fingerprinting technologique pour toutes les cibles."""
        results = {}
        
        # Filtrage des cibles avec ports web
        web_targets = []
        for subdomain, ports in port_results.items():
            if any(port in [80, 443, 8080, 8443] for port in ports):
                web_targets.append(subdomain)
        
        print(f"[+] Fingerprinting {len(web_targets)} web targets...")
        
        # Fingerprinting parallèle
        semaphore = asyncio.Semaphore(5)  # Limitation pour éviter la surcharge
        
        async def fingerprint_single_target(subdomain: str) -> tuple:
            async with semaphore:
                try:
                    tech_info = await self.tech_fingerprinter.fingerprint_url(f"https://{subdomain}")
                    return (subdomain, {"technologies": [{"name": t.name, "category": t.category, "confidence": t.confidence} for t in tech_info]})
                except Exception as e:
                    print(f"[!] Fingerprinting failed for {subdomain}: {e}")
                    return (subdomain, {})
        
        tasks = [fingerprint_single_target(target) for target in web_targets]
        fingerprint_results = await asyncio.gather(*tasks)
        
        for subdomain, tech_info in fingerprint_results:
            if tech_info:
                results[subdomain] = tech_info
                print(f"[+] {subdomain}: {len(tech_info.get('technologies', []))} technologies detected")
        
        return results
    
    async def _scan_vulnerabilities(self, tech_results: Dict) -> Dict:
        """Scan de vulnérabilités pour les cibles avec technologies détectées."""
        results = {
            'vulnerabilities': [],
            'targets_scanned': 0,
            'high_risk_count': 0,
            'medium_risk_count': 0,
            'low_risk_count': 0
        }
        
        targets_to_scan = list(tech_results.keys())
        print(f"[+] Vulnerability scanning {len(targets_to_scan)} targets...")
        
        for target in targets_to_scan:
            try:
                vulns = await self.vuln_scanner.scan_url(f"https://{target}")
                if vulns:
                    results['vulnerabilities'].extend(vulns)
                    results['targets_scanned'] += 1
                    
                    # Comptage par niveau de risque
                    for vuln in vulns:
                        if vuln.severity == 'HIGH':
                            results['high_risk_count'] += 1
                        elif vuln.severity == 'MEDIUM':
                            results['medium_risk_count'] += 1
                        else:
                            results['low_risk_count'] += 1
                    
                    print(f"[+] {target}: {len(vulns)} vulnerabilities found")
            
            except Exception as e:
                print(f"[!] Vulnerability scan failed for {target}: {e}")
        
        return results
    
    async def _capture_screenshots(self, port_results: Dict) -> Dict:
        """Capture d'écrans pour les cibles web."""
        results = {}
        
        # Filtrage des cibles web
        web_targets = []
        for subdomain, ports in port_results.items():
            if 80 in ports or 443 in ports:
                web_targets.append(subdomain)
        
        print(f"[+] Capturing screenshots for {len(web_targets)} web targets...")
        
        # Capture parallèle
        semaphore = asyncio.Semaphore(3)  # Limitation pour éviter la surcharge
        
        async def capture_single_screenshot(subdomain: str) -> tuple:
            async with semaphore:
                try:
                    result = await self.screenshot_capture.capture_single_url(f"https://{subdomain}")
                    return (subdomain, result.screenshot_path if result.success else None)
                except Exception as e:
                    print(f"[!] Screenshot failed for {subdomain}: {e}")
                    return (subdomain, None)
        
        tasks = [capture_single_screenshot(target) for target in web_targets]
        screenshot_results = await asyncio.gather(*tasks)
        
        for subdomain, screenshot_path in screenshot_results:
            if screenshot_path:
                results[subdomain] = screenshot_path
                print(f"[+] {subdomain}: Screenshot captured")
        
        return results
    
    async def _generate_reports(self, output_dir: str):
        """Génération des rapports finaux."""
        # Création du répertoire de sortie
        Path(output_dir).mkdir(exist_ok=True)
        
        # Export du log d'audit d'énumération
        if self.enumeration_engine.audit_log:
            audit_path = f"{output_dir}/enumeration_audit.json"
            self.enumeration_engine.export_audit_log(audit_path)
        
        # Génération des rapports
        timestamp = int(time.time())
        
        # Rapport JSON complet
        json_report_path = f"{output_dir}/smart_recon_report_{timestamp}.json"
        
        # Convertir les objets Vulnerability en dict pour la sérialisation JSON
        serializable_results = self._make_json_serializable(self.results)
        
        with open(json_report_path, 'w') as f:
            json.dump(serializable_results, f, indent=2)
        
        # Rapport HTML
        html_report_path = f"{output_dir}/smart_recon_report_{timestamp}.html"
        await self.report_generator.generate_html_report(
            self.results, html_report_path
        )
        
        print(f"[+] Reports generated:")
        print(f"    • JSON: {json_report_path}")
        print(f"    • HTML: {html_report_path}")
        if self.enumeration_engine.audit_log:
            print(f"    • Audit: {audit_path}")
    
    def _print_final_summary(self):
        """Affiche le résumé final de la reconnaissance."""
        summary = self.results['summary']
        
        print("\n" + "="*70)
        print("🎯 SMART RECONNAISSANCE COMPLETE")
        print("="*70)
        print(f"🎯 Target: {summary['target_domain']}")
        print(f"⏱️  Total Duration: {summary['total_duration']:.2f} seconds")
        print(f"🔍 Subdomains Found: {summary['subdomains_found']}")
        print(f"🎯 Targets Scanned: {summary['targets_scanned']}")
        print(f"🛡️  Vulnerabilities Found: {summary['vulnerabilities_found']}")
        print(f"📸 Screenshots Captured: {summary['screenshots_captured']}")
        
        # Détails des vulnérabilités
        vuln_results = self.results.get('vulnerability_scan', {})
        if vuln_results.get('vulnerabilities'):
            print(f"\n🚨 VULNERABILITY BREAKDOWN:")
            print(f"    • High Risk: {vuln_results.get('high_risk_count', 0)}")
            print(f"    • Medium Risk: {vuln_results.get('medium_risk_count', 0)}")
            print(f"    • Low Risk: {vuln_results.get('low_risk_count', 0)}")
        
        print("="*70)

    def _make_json_serializable(self, obj):
        """Convertit les objets non-sérialisables en dictionnaires."""
        if hasattr(obj, '__dict__'):
            return obj.__dict__
        elif isinstance(obj, list):
            return [self._make_json_serializable(item) for item in obj]
        elif isinstance(obj, dict):
            return {key: self._make_json_serializable(value) for key, value in obj.items()}
        else:
            return obj

async def main():
    """Point d'entrée principal."""
    parser = argparse.ArgumentParser(
        description="Aegir Smart Reconnaissance Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python smart_main.py example.com
  python smart_main.py example.com --output custom_reports
  python smart_main.py example.com --config custom_config.json
        """
    )
    
    parser.add_argument("domain", help="Target domain to enumerate")
    parser.add_argument("--output", "-o", default="reports", 
                       help="Output directory for reports (default: reports)")
    parser.add_argument("--config", "-c", help="Configuration file (JSON)")
    parser.add_argument("--confidence-level", "-cl", 
                       choices=["strict", "balanced", "aggressive"],
                       default="balanced",
                       help="Confidence level for subdomain filtering (default: balanced)")
    
    args = parser.parse_args()
    
    # Chargement de la configuration
    config = {}
    if args.config:
        try:
            with open(args.config, 'r') as f:
                config = json.load(f)
        except Exception as e:
            print(f"[!] Failed to load config: {e}")
            return
    
    # Ajustement de la config selon le niveau de confiance
    if 'enumeration' not in config:
        config['enumeration'] = {}
    if 'scoring' not in config['enumeration']:
        config['enumeration']['scoring'] = {}
    
    # Configuration du scoring selon le niveau de confiance
    confidence_configs = {
        "strict": {
            "min_confidence": 0.5,
            "min_sources": 2,
            "confidence_weight": 0.7,
            "source_count_weight": 0.3
        },
        "balanced": {
            "min_confidence": 0.3,
            "min_sources": 1,
            "confidence_weight": 0.6,
            "source_count_weight": 0.4
        },
        "aggressive": {
            "min_confidence": 0.2,
            "min_sources": 1,
            "confidence_weight": 0.5,
            "source_count_weight": 0.5
        }
    }
    
    config['enumeration']['scoring'] = confidence_configs[args.confidence_level]
    
    print(f"[+] Using confidence level: {args.confidence_level}")
    print(f"[+] Scoring config: {config['enumeration']['scoring']}")
    
    # Création de l'orchestrateur
    orchestrator = SmartReconOrchestrator(config)
    
    try:
        # Exécution de la reconnaissance
        results = await orchestrator.run_full_reconnaissance(args.domain, args.output)
        
        print(f"\n✅ Smart reconnaissance completed successfully!")
        print(f"📁 Check the '{args.output}' directory for detailed reports.")
        
    except KeyboardInterrupt:
        print("\n[!] Reconnaissance interrupted by user")
    except Exception as e:
        print(f"\n[!] Reconnaissance failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(main()) 