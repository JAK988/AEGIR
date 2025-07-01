# 🔥 AEGIR - Offensive Reconnaissance Tool

**AEGIR** est un outil de reconnaissance offensive automatisé et professionnel qui combine énumération de sous-domaines, scan de ports, fingerprinting technologique, capture d'écrans et analyse de vulnérabilités en un seul workflow intégré.

## 🚀 Fonctionnalités

### 🔍 Énumération de Sous-domaines
- **Sources multiples** : Certificate Transparency (crt.sh), HackerTarget API, DNS brute force
- **Déduplication intelligente** : Résolution CNAME, normalisation, élimination des doublons
- **Filtrage wildcard** : Détection et élimination automatique des faux positifs DNS
- **Wordlist configurable** : 60+ mots courants + extensible

### 🔌 Scan de Ports
- **Scan asynchrone** : httpx pour les ports web, socket pour les autres services
- **Détection de services** : 30+ ports courants mappés (HTTP, HTTPS, SSH, FTP, etc.)
- **Extraction de métadonnées** : Status HTTP, titre, headers, temps de réponse
- **Rate limiting** : Contrôle de la charge réseau et respect des limites

### 🧬 Fingerprinting Technologique
- **Signatures avancées** : Headers HTTP, contenu HTML/JS, meta tags
- **6 catégories** : Web Frameworks, Web Servers, Programming Languages, Cloud Platforms, Databases, DevOps Tools
- **Scoring de confiance** : 70-90% selon la fiabilité des signatures
- **Extraction de versions** : Parsing automatique des headers

### 📸 Capture d'Écrans
- **Playwright headless** : Capture haute qualité en 1920x1080
- **Rotation User-Agent** : 5 User-Agents différents pour éviter la détection
- **Gestion des timeouts** : 30s par page avec attente du chargement complet
- **Nommage intelligent** : Fichiers organisés par domaine/port

### 🛡️ Analyse de Vulnérabilités
- **Headers de sécurité** : HSTS, CSP, X-Frame-Options, etc.
- **Divulgation d'informations** : Headers serveur, listing de répertoires
- **Authentification** : Endpoints sensibles sans protection
- **Configuration** : Mode debug, erreurs détaillées
- **Scoring CVSS** : Évaluation automatique du niveau de risque

### 📊 Rapports Professionnels
- **Export JSON** : Données structurées pour intégration
- **Export HTML** : Rapport visuel avec métriques et screenshots
- **Résumé CLI** : Statistiques en temps réel
- **Corrélation** : Lien entre services, technologies et vulnérabilités

## 🛠️ Installation

### Prérequis
- Python 3.8+
- pip3

### Installation des dépendances
```bash
# Installation des packages Python
pip3 install httpx dnspython beautifulsoup4 playwright

# Installation du navigateur Playwright
playwright install chromium
```

### Installation rapide
```bash
git clone <repository>
cd AEGIR
pip3 install -r requirements.txt
playwright install chromium
```

## 📖 Utilisation

### Scan basique
```bash
python3 main.py example.com
```

### Scan avec rapport personnalisé
```bash
python3 main.py example.com --output my_report
```

### Exemple de sortie
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

### Modules principaux
```
AEGIR/
├── main.py                 # Orchestrateur principal
├── subdomain_enum.py       # Énumération de sous-domaines
├── port_scanner.py         # Scan de ports
├── tech_fingerprint.py     # Fingerprinting technologique
├── screenshot_capture.py   # Capture d'écrans
├── vuln_scanner.py         # Analyse de vulnérabilités
└── README.md              # Documentation
```

### Workflow
1. **Énumération** → Découverte des sous-domaines
2. **Scan de ports** → Identification des services actifs
3. **Fingerprinting** → Détection des technologies
4. **Capture d'écrans** → Documentation visuelle
5. **Analyse vulnérabilités** → Évaluation des risques
6. **Agrégation** → Corrélation des résultats
7. **Export** → Génération des rapports

## 📊 Exemples de Rapports

### Résumé JSON
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

### Rapport HTML
- **Résumé exécutif** avec métriques clés
- **Services découverts** avec technologies et vulnérabilités
- **Screenshots intégrés** pour documentation visuelle
- **Code couleur** pour les niveaux de vulnérabilité

## 🔧 Configuration Avancée

### Personnalisation des ports
```python
# Dans main.py
self.web_ports = [80, 443, 8080, 8443, 3000, 4000, 5000, 8000, 9000]
```

### Ajout de signatures technologiques
```python
# Dans tech_fingerprint.py
"New Framework": {
    "headers": ["x-powered-by"],
    "html": ["new-framework"],
    "js": ["NewFramework"],
    "confidence": 85
}
```

### Configuration des vulnérabilités
```python
# Dans vuln_scanner.py
"Custom Vulnerability": {
    "description": "Description personnalisée",
    "severity": "HIGH",
    "indicators": ["custom-indicator"],
    "cvss_score": 7.5
}
```

## 🎯 Cas d'Usage

### Pentest Externe
```bash
# Scan complet d'un domaine cible
python3 main.py target-company.com --output pentest_report
```

### Bug Bounty
```bash
# Scan rapide pour identification de surface d'attaque
python3 main.py bugbounty-target.com
```

### Audit de Sécurité
```bash
# Documentation complète pour rapport d'audit
python3 main.py audit-domain.com --output security_audit
```

## ⚡ Performance

### Optimisations
- **Scan asynchrone** : Parallélisation des requêtes
- **Rate limiting** : Respect des limites de bande passante
- **Cache DNS** : Réutilisation des résolutions
- **Timeouts** : Gestion des services lents

### Métriques typiques
- **100 sous-domaines** : ~2-3 minutes
- **50 services web** : ~1-2 minutes
- **Capture d'écrans** : ~30s par page
- **Analyse vulnérabilités** : ~5s par service

## 🔒 Sécurité et Éthique

### Bonnes pratiques
- **Autorisation** : Toujours obtenir une autorisation écrite
- **Rate limiting** : Respecter les limites des services
- **Logs** : Documenter toutes les activités
- **Rapports** : Classifier les informations sensibles

### Limitations
- **Scope** : Respecter le périmètre défini
- **Impact** : Éviter les tests destructifs
- **Légalité** : Conformité aux lois locales

## 🤝 Contribution

### Développement
1. Fork le projet
2. Créer une branche feature
3. Implémenter les améliorations
4. Tester exhaustivement
5. Soumettre une pull request

### Améliorations souhaitées
- [ ] Intégration Nuclei
- [ ] Scan SSL/TLS avancé
- [ ] Détection de WAF
- [ ] API REST
- [ ] Interface web
- [ ] Intégration CI/CD

## 📄 Licence

Ce projet est sous licence MIT. Voir le fichier `LICENSE` pour plus de détails.

## ⚠️ Avertissement

**AEGIR est un outil de test de pénétration. Son utilisation doit être strictement limitée aux environnements autorisés. Les auteurs ne sont pas responsables de l'utilisation abusive de cet outil.**

## 📞 Support

- **Issues** : GitHub Issues
- **Documentation** : README.md
- **Exemples** : Dossier `examples/`

---

**AEGIR** - Outil de reconnaissance offensive professionnel 🔥 

## 🙏 Crédits

Développé et orchestré par **Antoine Kojfer (JAK) Disconnect**

---

## 📝 Note de version et Roadmap

### Version 1.0 — Proof of Concept Avancé
- Architecture modulaire, pipeline complet, configuration externalisée, logging structuré, selftests réutilisables.
- Développé par Antoine Kojfer (JAK) - Senior Security Researcher
- Statut : Proof of Concept avancé, prêt pour évaluation, non production-ready.

### Roadmap de développement
- **v1.1** : Tests de robustesse, vulnérabilités avancées, gestion d'erreurs
- **v1.2** : Performance, API REST, monitoring
- **v2.0** : Wordlists, reporting avancé, configuration avancée
- **v2.1+** : Interface utilisateur, IA, collaboration

### Recommandation
> "Aegir est un excellent proof of concept, propre, modulaire, documenté, mais nécessite des améliorations critiques pour un usage production. Suivre la roadmap pour garantir la robustesse, la sécurité et l'intégration."

--- 