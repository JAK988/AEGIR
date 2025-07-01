import json
from pathlib import Path

class ReportGenerator:
    """Générateur de rapport HTML minimal pour Aegir."""
    
    async def generate_html_report(self, results: dict, output_path: str):
        """Génère un rapport HTML simple à partir des résultats globaux."""
        html = self._build_html(results)
        Path(output_path).write_text(html, encoding='utf-8')
    
    def _build_html(self, results: dict) -> str:
        """Construit le HTML minimal du rapport."""
        summary = results.get('summary', {})
        enumeration = results.get('enumeration', {})
        port_scan = results.get('port_scan', {})
        tech_fingerprint = results.get('tech_fingerprint', {})
        vuln_scan = results.get('vulnerability_scan', {})
        screenshots = results.get('screenshots', {})
        
        # Vue unifiée subdomain-to-service
        unified_view = self._build_unified_view(enumeration, port_scan, tech_fingerprint, vuln_scan, screenshots)
        
        html = f"""
<!DOCTYPE html>
<html lang='en'>
<head>
    <meta charset='UTF-8'>
    <title>Aegir Smart Recon Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; background: #f8f8f8; color: #222; }}
        h1, h2, h3 {{ color: #2c3e50; }}
        .section {{ background: #fff; margin: 2em 0; padding: 1em 2em; border-radius: 8px; box-shadow: 0 2px 8px #eee; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background: #f0f0f0; }}
        .vuln-high {{ color: #c0392b; font-weight: bold; }}
        .vuln-medium {{ color: #e67e22; font-weight: bold; }}
        .vuln-low {{ color: #27ae60; font-weight: bold; }}
        .subdomain-row {{ background: #f9f9f9; }}
        .tech-badge {{ background: #3498db; color: white; padding: 2px 6px; border-radius: 3px; font-size: 0.8em; margin: 1px; }}
        .port-badge {{ background: #e74c3c; color: white; padding: 2px 6px; border-radius: 3px; font-size: 0.8em; margin: 1px; }}
        .screenshot-link {{ color: #2980b9; text-decoration: none; }}
        .screenshot-link:hover {{ text-decoration: underline; }}
        .summary-stats {{ display: flex; justify-content: space-around; margin: 1em 0; }}
        .stat-box {{ background: #ecf0f1; padding: 1em; border-radius: 5px; text-align: center; }}
        .stat-number {{ font-size: 2em; font-weight: bold; color: #2c3e50; }}
        .stat-label {{ color: #7f8c8d; }}
    </style>
</head>
<body>
    <h1>🔍 AEGIR SMART RECON REPORT</h1>
    
    <div class='section'>
        <h2>📊 Executive Summary</h2>
        <div class='summary-stats'>
            <div class='stat-box'>
                <div class='stat-number'>{summary.get('subdomains_found',0)}</div>
                <div class='stat-label'>Subdomains</div>
            </div>
            <div class='stat-box'>
                <div class='stat-number'>{summary.get('targets_scanned',0)}</div>
                <div class='stat-label'>Targets Scanned</div>
            </div>
            <div class='stat-box'>
                <div class='stat-number'>{summary.get('vulnerabilities_found',0)}</div>
                <div class='stat-label'>Vulnerabilities</div>
            </div>
            <div class='stat-box'>
                <div class='stat-number'>{summary.get('screenshots_captured',0)}</div>
                <div class='stat-label'>Screenshots</div>
            </div>
        </div>
        <ul>
            <li><b>Target:</b> {summary.get('target_domain','')}</li>
            <li><b>Duration:</b> {summary.get('total_duration',0):.2f} seconds</li>
        </ul>
    </div>

    <div class='section'>
        <h2>🎯 Subdomain-to-Service Mapping (Unified View)</h2>
        <p><em>Automated correlation: subdomains ↔ ports ↔ tech stack ↔ vulnerabilities ↔ screenshots</em></p>
        {unified_view}
    </div>

    <div class='section'>
        <h2>🔍 Subdomain Enumeration</h2>
        <ul>
        {''.join(f'<li>{sub}</li>' for sub in enumeration.get('subdomains', [])) or '<li>No subdomains found.</li>'}
        </ul>
    </div>
    
    <div class='section'>
        <h2>🔌 Port Scan Results</h2>
        <table>
            <tr><th>Subdomain</th><th>Open Ports</th></tr>
            {''.join(f'<tr><td>{sub}</td><td>{", ".join(str(p) for p in ports)}</td></tr>' for sub, ports in port_scan.items()) or '<tr><td colspan=2>No open ports found.</td></tr>'}
        </table>
    </div>
    
    <div class='section'>
        <h2>🔬 Technology Fingerprinting</h2>
        <table>
            <tr><th>Subdomain</th><th>Technologies</th></tr>
            {''.join(f'<tr><td>{sub}</td><td>{", ".join(t.get("name","?") for t in techs.get("technologies", []))}</td></tr>' for sub, techs in tech_fingerprint.items()) or '<tr><td colspan=2>No technologies detected.</td></tr>'}
        </table>
    </div>
    
    <div class='section'>
        <h2>🛡️ Vulnerability Scan</h2>
        <table>
            <tr><th>Target</th><th>Vulnerability</th><th>Severity</th><th>Description</th></tr>
            {''.join(f'<tr><td>{getattr(v, "target", "?")}</td><td>{getattr(v, "name", "?")}</td><td class="vuln-{getattr(v, "severity", "low").lower()}">{getattr(v, "severity", "?")}</td><td>{getattr(v, "description", "?")}</td></tr>' for v in vuln_scan.get('vulnerabilities', [])) or '<tr><td colspan=4>No vulnerabilities found.</td></tr>'}
        </table>
    </div>
    
    <div class='section'>
        <h2>📸 Screenshots</h2>
        <ul>
        {''.join(f'<li>{sub}: <a href="{path}" class="screenshot-link" target="_blank">{path}</a></li>' for sub, path in screenshots.items()) or '<li>No screenshots captured.</li>'}
        </ul>
    </div>
    
    <div class='section'>
        <h2>📄 Raw JSON</h2>
        <pre style='background:#f4f4f4; padding:1em; border-radius:6px; max-height:300px; overflow:auto;'>
{self._safe_json_dump(results)}
        </pre>
    </div>
</body>
</html>
"""
        return html
    
    def _build_unified_view(self, enumeration, port_scan, tech_fingerprint, vuln_scan, screenshots):
        """Construit la vue unifiée subdomain-to-service."""
        subdomains = enumeration.get('subdomains', [])
        
        if not subdomains:
            return "<p>No subdomains found.</p>"
        
        # Grouper les vulnérabilités par target
        vulns_by_target = {}
        for vuln in vuln_scan.get('vulnerabilities', []):
            # Gérer les objets Vulnerability (dataclass) et les dict
            if hasattr(vuln, 'target'):
                target = vuln.target.replace('https://', '').replace('http://', '')
            else:
                target = str(vuln).replace('https://', '').replace('http://', '')
            
            if target not in vulns_by_target:
                vulns_by_target[target] = []
            vulns_by_target[target].append(vuln)
        
        rows = []
        for subdomain in subdomains:
            # Ports
            ports = port_scan.get(subdomain, [])
            ports_html = ' '.join([f'<span class="port-badge">{p}</span>' for p in ports])
            
            # Technologies
            techs = tech_fingerprint.get(subdomain, {}).get('technologies', [])
            techs_html = ' '.join([f'<span class="tech-badge">{t.get("name", "?")}</span>' for t in techs[:5]])  # Limiter à 5
            if len(techs) > 5:
                techs_html += f' <span class="tech-badge">+{len(techs)-5} more</span>'
            
            # Vulnérabilités
            vulns = vulns_by_target.get(subdomain, [])
            vulns_html = ' '.join([f'<span class="vuln-{getattr(v, "severity", "low").lower()}">{getattr(v, "name", "?")}</span>' for v in vulns[:3]])  # Limiter à 3
            if len(vulns) > 3:
                vulns_html += f' <span class="vuln-low">+{len(vulns)-3} more</span>'
            
            # Screenshot
            screenshot_path = screenshots.get(subdomain, '')
            screenshot_html = f'<a href="{screenshot_path}" class="screenshot-link" target="_blank">View</a>' if screenshot_path else 'N/A'
            
            rows.append(f"""
            <tr class="subdomain-row">
                <td><strong>{subdomain}</strong></td>
                <td>{ports_html or 'None'}</td>
                <td>{techs_html or 'None'}</td>
                <td>{vulns_html or 'None'}</td>
                <td>{screenshot_html}</td>
            </tr>
            """)
        
        return f"""
        <table>
            <tr>
                <th>Subdomain</th>
                <th>Open Ports</th>
                <th>Technologies</th>
                <th>Vulnerabilities</th>
                <th>Screenshot</th>
            </tr>
            {''.join(rows)}
        </table>
        """ 
    
    def _safe_json_dump(self, obj, max_length=5000):
        """Sérialisation JSON sécurisée avec gestion d'erreurs."""
        try:
            # Convertir les objets non-sérialisables
            serializable_obj = self._make_json_serializable(obj)
            json_str = json.dumps(serializable_obj, indent=2, default=str)
            
            if len(json_str) > max_length:
                return json_str[:max_length] + "\n... (truncated)"
            return json_str
            
        except Exception as e:
            return f"Error serializing JSON: {str(e)}\n\nPartial data available in individual sections above."
    
    def _make_json_serializable(self, obj):
        """Convertit les objets non-sérialisables en dictionnaires."""
        if hasattr(obj, '__dict__'):
            return obj.__dict__
        elif isinstance(obj, list):
            return [self._make_json_serializable(item) for item in obj]
        elif isinstance(obj, dict):
            return {key: self._make_json_serializable(value) for key, value in obj.items()}
        else:
            return str(obj) 