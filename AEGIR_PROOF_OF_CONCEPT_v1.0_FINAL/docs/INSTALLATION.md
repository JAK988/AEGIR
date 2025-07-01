# Installation AEGIR

## Prérequis
- Python 3.8+
- pip3

## Installation
```bash
git clone <repository>
cd AEGIR
pip3 install -r requirements.txt
playwright install chromium
```

## Test
```bash
python3 aegir.py example.com
```

## Prérequis

### Système d'exploitation
- **macOS** 10.15+ (testé sur macOS 21.4.0)
- **Linux** Ubuntu 18.04+ / CentOS 7+
- **Windows** 10+ (avec WSL recommandé)

### Python
- **Python 3.8+** (recommandé: Python 3.12)
- **pip3** (gestionnaire de packages)

### Navigateur
- **Chromium** (installé automatiquement par Playwright)

## Installation Détaillée

### Étape 1: Vérifier Python
```bash
python3 --version
# Doit afficher Python 3.8.0 ou supérieur
```

### Étape 2: Créer un Environnement Virtuel (Recommandé)
```bash
python3 -m venv aegir_env
source aegir_env/bin/activate  # Linux/macOS
# ou
aegir_env\Scripts\activate     # Windows
```

### Étape 3: Installer les Packages
```bash
pip3 install --upgrade pip
pip3 install -r requirements.txt
```

### Étape 4: Installer Playwright
```bash
playwright install chromium
```

### Étape 5: Vérifier l'Installation
```bash
python3 -c "import httpx, dns.resolver, playwright; print('✅ Installation réussie!')"
```

## Dépendances Détaillées

### Packages Python Principaux
- **httpx** (0.24.0+) : Client HTTP asynchrone
- **dnspython** (2.3.0+) : Résolution DNS
- **beautifulsoup4** (4.12.0+) : Parsing HTML
- **playwright** (1.40.0+) : Automatisation navigateur
- **requests** (2.31.0+) : Client HTTP synchrone
- **typer** (0.9.0+) : Interface CLI
- **pandas** (2.0.0+) : Manipulation données

### Dépendances Système
- **Git** : Clonage du repository
- **curl/wget** : Téléchargements
- **unzip** : Extraction d'archives

## Résolution de Problèmes

### Erreur: "playwright: command not found"
```bash
# Réinstaller playwright
pip3 uninstall playwright
pip3 install playwright
playwright install chromium
```

### Erreur: "Permission denied"
```bash
# Donner les permissions d'exécution
chmod +x aegir.py
```

### Erreur: "Module not found"
```bash
# Vérifier l'installation des packages
pip3 list | grep -E "(httpx|dns|beautifulsoup|playwright)"
```

### Erreur: "Chromium not found"
```bash
# Réinstaller Chromium
playwright install --force chromium
```

## Configuration Avancée

### Variables d'Environnement
```bash
export AEGIR_TIMEOUT=30
export AEGIR_RATE_LIMIT=0.1
export AEGIR_MAX_WORKERS=10
```

### Configuration Proxy
```bash
export HTTP_PROXY=http://proxy:8080
export HTTPS_PROXY=http://proxy:8080
```

## Vérification de l'Installation

### Test Complet
```bash
# Test sur une plateforme légale
python3 aegir.py httpbin.org --output test_install

# Vérifier les résultats
ls -la test_install*
```

### Test des Modules Individuels
```bash
# Test énumération
python3 -c "from src.core.subdomain_enum import enumerate_subdomains; print(enumerate_subdomains('example.com'))"

# Test scan de ports
python3 -c "import asyncio; from src.core.port_scanner import quick_port_scan; print(asyncio.run(quick_port_scan('example.com', [80, 443])))"
```

## Mise à Jour

### Mettre à Jour AEGIR
```bash
git pull origin main
pip3 install -r requirements.txt --upgrade
playwright install --force chromium
```

### Mettre à Jour les Dépendances
```bash
pip3 list --outdated
pip3 install --upgrade <package-name>
```

## Support

### Logs d'Installation
```bash
# Activer les logs détaillés
export PYTHONVERBOSE=1
python3 aegir.py example.com
```

### Documentation
- **README.md** : Guide principal
- **docs/** : Documentation détaillée
- **examples/** : Exemples d'utilisation

### Issues
- Vérifier les issues GitHub existantes
- Créer une nouvelle issue avec les logs d'erreur 