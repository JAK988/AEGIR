import requests
import dns.resolver
import json
import time
import asyncio
from typing import List, Set, Optional
from urllib.parse import urlparse
from dataclasses import dataclass

@dataclass
class EnumerationResult:
    """Résultat de l'énumération avec métadonnées."""
    subdomains: List[str]
    total_discovered: int
    after_deduplication: int
    after_wildcard_filter: int
    sources_used: List[str]
    errors: List[str]

def get_certificate_transparency(domain: str, timeout: float = 10.0) -> Set[str]:
    """Récupère les sous-domaines via Certificate Transparency logs."""
    discovered = set()
    try:
        # Utiliser l'API crt.sh
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        response = requests.get(url, timeout=timeout)
        if response.status_code == 200:
            data = response.json()
            for entry in data:
                name = entry.get('name_value', '').lower().strip()
                if domain in name and '*' not in name:
                    if name.endswith(f'.{domain}'):
                        discovered.add(name)
    except Exception:
        pass
    return discovered

def get_dns_dumpster(domain: str) -> Set[str]:
    """Récupère les sous-domaines via DNSDumpster (simulation)."""
    subdomains = set()
    try:
        # Simulation - en réalité il faudrait parser le site
        # Pour l'instant on retourne quelques sous-domaines courants
        common_subs = ['www', 'mail', 'ftp', 'admin', 'blog', 'api', 'cdn', 'static']
        for sub in common_subs:
            subdomains.add(f"{sub}.{domain}")
    except Exception as e:
        print(f"[!] Erreur DNSDumpster: {e}")
    return subdomains

def get_hackertarget_api(domain: str, timeout: float = 10.0) -> Set[str]:
    """Récupère les sous-domaines via HackerTarget API."""
    discovered = set()
    try:
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        response = requests.get(url, timeout=timeout)
        if response.status_code == 200 and response.text:
            lines = response.text.strip().split('\n')
            for line in lines:
                if ',' in line:
                    subdomain = line.split(',')[0].strip()
                    if subdomain and domain in subdomain:
                        discovered.add(subdomain)
    except Exception:
        pass
    return discovered

def get_default_wordlist() -> List[str]:
    """Retourne une wordlist par défaut pour le brute-force DNS."""
    return [
        'www', 'mail', 'ftp', 'admin', 'blog', 'dev', 'test', 'staging',
        'api', 'cdn', 'static', 'assets', 'img', 'images', 'media',
        'support', 'help', 'docs', 'wiki', 'forum', 'shop', 'store',
        'app', 'mobile', 'm', 'secure', 'login', 'auth', 'dashboard',
        'panel', 'cpanel', 'webmail', 'ns1', 'ns2', 'mx', 'smtp',
        'pop', 'imap', 'vpn', 'remote', 'ssh', 'telnet', 'dns',
        'gateway', 'router', 'firewall', 'proxy', 'cache', 'loadbalancer',
        'jenkins', 'gitlab', 'github', 'jira', 'confluence', 'sonar',
        'nexus', 'artifactory', 'docker', 'kubernetes', 'k8s', 'helm',
        'prometheus', 'grafana', 'elk', 'elasticsearch', 'kibana',
        'logstash', 'zabbix', 'nagios', 'monitoring', 'ci', 'cd',
        'aws', 'azure', 'gcp', 'cloud', 'ec2', 's3', 'lambda',
        'cloudfront', 'route53', 'rds', 'dynamodb', 'sqs', 'sns'
    ]

def detect_wildcard_dns(domain: str, timeout: float = 5.0) -> bool:
    """
    Détecte la présence d'un wildcard DNS sur le domaine.
    
    Args:
        domain: Le domaine à tester
        timeout: Timeout pour la résolution DNS
    
    Returns:
        bool: True si un wildcard DNS est détecté
    """
    test_label = f"aegir-wildcard-test-{int(time.time())}"
    test_subdomain = f"{test_label}.{domain}"
    
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        
        answers = resolver.resolve(test_subdomain, 'A')
        return len(answers) > 0
    except dns.resolver.NXDOMAIN:
        return False
    except Exception:
        return False

def dns_brute_force(domain: str, wordlist: Optional[List[str]] = None, 
                   timeout: float = 2.0, rate_limit: float = 0.1) -> Set[str]:
    """
    Brute force DNS avec une wordlist donnée.
    
    Args:
        domain: Le domaine cible
        wordlist: Liste de mots à tester (utilise la liste par défaut si None)
        timeout: Timeout par requête DNS
        rate_limit: Délai entre chaque requête
    
    Returns:
        Set[str]: Ensemble des sous-domaines découverts
    """
    if wordlist is None:
        wordlist = get_default_wordlist()
    
    discovered = set()
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    
    for word in wordlist:
        subdomain = f"{word}.{domain}"
        try:
            answers = resolver.resolve(subdomain, 'A')
            if answers:
                discovered.add(subdomain)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
            pass
        except Exception:
            pass
        
        time.sleep(rate_limit)
    
    return discovered

def deduplicate_subdomains(subdomains: Set[str], domain: str) -> Set[str]:
    """
    Déduplique les sous-domaines en résolvant les CNAME et en normalisant.
    
    Args:
        subdomains: Ensemble des sous-domaines à dédupliquer
        domain: Le domaine parent
    
    Returns:
        Set[str]: Ensemble des sous-domaines dédupliqués
    """
    if not subdomains:
        return set()
    
    # Normalisation basique
    normalized = set()
    for sub in subdomains:
        if sub and domain in sub and not sub.startswith('*'):
            normalized.add(sub.lower().strip())
    
    # Résolution CNAME pour dédupliquer
    cname_map = {}
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2.0
    
    for subdomain in normalized:
        try:
            answers = resolver.resolve(subdomain, 'CNAME')
            if answers:
                canonical_name = str(answers[0]).rstrip('.')
                cname_map[subdomain] = canonical_name
        except Exception:
            pass
    
    # Garder le sous-domaine le plus court pour chaque CNAME
    final_subdomains = set()
    cname_groups = {}
    
    for subdomain, cname in cname_map.items():
        if cname not in cname_groups:
            cname_groups[cname] = []
        cname_groups[cname].append(subdomain)
    
    for cname, subdomains_list in cname_groups.items():
        shortest = min(subdomains_list, key=len)
        final_subdomains.add(shortest)
    
    # Ajouter les sous-domaines sans CNAME
    for subdomain in normalized:
        if subdomain not in cname_map:
            final_subdomains.add(subdomain)
    
    return final_subdomains

def filter_wildcard_subdomains(subdomains: Set[str], domain: str, 
                              timeout: float = 2.0) -> Set[str]:
    """
    Filtre les sous-domaines qui correspondent au wildcard DNS.
    
    Args:
        subdomains: Ensemble des sous-domaines à filtrer
        domain: Le domaine parent
        timeout: Timeout pour la résolution DNS
    
    Returns:
        Set[str]: Ensemble des sous-domaines filtrés
    """
    if not detect_wildcard_dns(domain, timeout):
        return subdomains
    
    test_label = f"aegir-wildcard-test-{int(time.time())}"
    test_subdomain = f"{test_label}.{domain}"
    
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        
        wildcard_answers = resolver.resolve(test_subdomain, 'A')
        wildcard_ips = set(str(a) for a in wildcard_answers)
        
        filtered = set()
        for subdomain in subdomains:
            try:
                answers = resolver.resolve(subdomain, 'A')
                subdomain_ips = set(str(a) for a in answers)
                
                # Si les IPs ne se chevauchent pas avec le wildcard
                if not subdomain_ips.intersection(wildcard_ips):
                    filtered.add(subdomain)
            except Exception:
                # En cas d'erreur, on garde le sous-domaine (prudent)
                filtered.add(subdomain)
        
        return filtered
    except Exception:
        # En cas d'erreur, on retourne tous les sous-domaines
        return subdomains

def enumerate_subdomains(domain: str, 
                        wordlist: Optional[List[str]] = None,
                        enable_wildcard_filter: bool = True,
                        timeout: float = 5.0,
                        rate_limit: float = 0.1) -> List[str]:
    """
    Enumère les sous-domaines d'un domaine donné.
    
    Args:
        domain: Le domaine cible (ex: 'example.com')
        wordlist: Liste de mots pour le brute-force (utilise la liste par défaut si None)
        enable_wildcard_filter: Active le filtrage des wildcards DNS
        timeout: Timeout pour les requêtes DNS/HTTP
        rate_limit: Délai entre les requêtes DNS
    
    Returns:
        List[str]: Liste des sous-domaines découverts, triée alphabétiquement
    """
    all_subdomains = set()
    sources_used = []
    errors = []
    
    # 1. Certificate Transparency
    try:
        ct_subs = get_certificate_transparency(domain, timeout)
        all_subdomains.update(ct_subs)
        sources_used.append("certificate_transparency")
    except Exception as e:
        errors.append(f"Certificate Transparency error: {str(e)}")
    
    # 2. HackerTarget API
    try:
        ht_subs = get_hackertarget_api(domain, timeout)
        all_subdomains.update(ht_subs)
        sources_used.append("hackertarget_api")
    except Exception as e:
        errors.append(f"HackerTarget API error: {str(e)}")
    
    # 3. DNS Brute Force
    try:
        bf_subs = dns_brute_force(domain, wordlist, timeout, rate_limit)
        all_subdomains.update(bf_subs)
        sources_used.append("dns_brute_force")
    except Exception as e:
        errors.append(f"DNS brute force error: {str(e)}")
    
    total_discovered = len(all_subdomains)
    
    # 4. Déduplication
    deduplicated = deduplicate_subdomains(all_subdomains, domain)
    after_deduplication = len(deduplicated)
    
    # 5. Filtrage wildcard (optionnel)
    if enable_wildcard_filter:
        final_subs = filter_wildcard_subdomains(deduplicated, domain, timeout)
        after_wildcard_filter = len(final_subs)
    else:
        final_subs = deduplicated
        after_wildcard_filter = after_deduplication
    
    # Retourner la liste triée
    return sorted(list(final_subs))

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python3 subdomain_enum.py <domain>")
        sys.exit(1)
    
    domain = sys.argv[1]
    subdomains = enumerate_subdomains(domain)
    
    print(f"\nSous-domaines trouvés pour {domain}:")
    for sub in subdomains:
        print(f"  - {sub}") 