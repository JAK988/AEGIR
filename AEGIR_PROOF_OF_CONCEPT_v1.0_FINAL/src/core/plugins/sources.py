"""
Sources d'énumération concrètes pour Aegir
Implémentations des plugins d'énumération de sous-domaines
"""

import asyncio
import aiohttp
import dns.resolver
import time
from typing import List, Dict, Set, Optional
from . import EnumerationSource, EnumerationResult, SourceConfig

class CertificateTransparencySource(EnumerationSource):
    """Source d'énumération via Certificate Transparency logs."""
    
    def __init__(self, config: SourceConfig = None):
        if config is None:
            config = SourceConfig(
                name="certificate_transparency",
                timeout=15.0,
                rate_limit=0.2,
                max_retries=2
            )
        super().__init__(config)
    
    async def enumerate(self, domain: str) -> List[EnumerationResult]:
        """Énumère via Certificate Transparency."""
        results = []
        start_time = time.time()
        
        try:
            # API crt.sh
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.config.timeout)) as session:
                async with session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        for entry in data:
                            name = entry.get('name_value', '').lower().strip()
                            if domain in name and '*' not in name and name.endswith(f'.{domain}'):
                                result = EnumerationResult(
                                    subdomain=name,
                                    source_name=self.config.name,
                                    confidence=0.8,  # CT logs sont fiables
                                    metadata={
                                        'issuer': entry.get('issuer_name', ''),
                                        'not_before': entry.get('not_before', ''),
                                        'not_after': entry.get('not_after', '')
                                    },
                                    timestamp=time.time(),
                                    response_time=time.time() - start_time
                                )
                                results.append(result)
        
        except Exception as e:
            self.errors.append(f"CT enumeration failed: {str(e)}")
        
        return results
    
    def get_source_info(self) -> Dict:
        return {
            'name': 'Certificate Transparency',
            'description': 'Enumeration via CT logs (crt.sh)',
            'reliability': 'High',
            'speed': 'Medium',
            'coverage': 'Good'
        }

class DnsBruteForceSource(EnumerationSource):
    """Source d'énumération via brute force DNS."""
    
    def __init__(self, config: SourceConfig = None):
        if config is None:
            config = SourceConfig(
                name="dns_brute_force",
                timeout=5.0,
                rate_limit=0.1,
                max_retries=1,
                custom_params={
                    'wordlist': self.get_default_wordlist(),
                    'max_concurrent': 20
                }
            )
        super().__init__(config)
    
    async def enumerate(self, domain: str) -> List[EnumerationResult]:
        """Énumère via brute force DNS."""
        results = []
        wordlist = self.config.custom_params.get('wordlist', self.get_default_wordlist())
        max_concurrent = self.config.custom_params.get('max_concurrent', 20)
        
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def check_subdomain(word: str) -> Optional[EnumerationResult]:
            async with semaphore:
                subdomain = f"{word}.{domain}"
                start_time = time.time()
                
                try:
                    resolver = dns.resolver.Resolver()
                    resolver.timeout = 2.0
                    answers = resolver.resolve(subdomain, 'A')
                    
                    if answers:
                        result = EnumerationResult(
                            subdomain=subdomain,
                            source_name=self.config.name,
                            confidence=0.7,  # DNS résolu = cible valide
                            metadata={
                                'ip': str(answers[0]),
                                'word': word
                            },
                            timestamp=time.time(),
                            response_time=time.time() - start_time
                        )
                        return result
                
                except Exception:
                    pass
                
                await asyncio.sleep(self.config.rate_limit)
                return None
        
        # Exécution parallèle
        tasks = [check_subdomain(word) for word in wordlist]
        subdomain_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in subdomain_results:
            if isinstance(result, EnumerationResult):
                results.append(result)
        
        return results
    
    def get_default_wordlist(self) -> List[str]:
        """Wordlist par défaut intelligente."""
        return [
            'www', 'mail', 'ftp', 'admin', 'blog', 'api', 'cdn', 'static',
            'support', 'help', 'docs', 'wiki', 'forum', 'shop', 'store',
            'app', 'mobile', 'secure', 'login', 'auth', 'dashboard',
            'panel', 'cpanel', 'webmail', 'ns1', 'ns2', 'mx', 'smtp',
            'dev', 'test', 'staging', 'prod', 'internal', 'vpn', 'remote'
        ]
    
    def get_source_info(self) -> Dict:
        return {
            'name': 'DNS Brute Force',
            'description': 'Enumeration via DNS brute force',
            'reliability': 'Medium',
            'speed': 'Slow',
            'coverage': 'Good'
        }

class SearchEngineSource(EnumerationSource):
    """Source d'énumération via moteurs de recherche (simulation)."""
    
    def __init__(self, config: SourceConfig = None):
        if config is None:
            config = SourceConfig(
                name="search_engines",
                timeout=10.0,
                rate_limit=1.0,  # Plus lent pour éviter le rate limiting
                max_retries=2
            )
        super().__init__(config)
    
    async def enumerate(self, domain: str) -> List[EnumerationResult]:
        """Énumère via moteurs de recherche (simulation pour l'instant)."""
        results = []
        start_time = time.time()
        
        # Simulation - en réalité on utiliserait Google, Bing, etc.
        # Pour l'instant on retourne des sous-domaines courants
        common_subs = ['www', 'mail', 'ftp', 'admin', 'blog', 'api']
        
        for sub in common_subs:
            subdomain = f"{sub}.{domain}"
            result = EnumerationResult(
                subdomain=subdomain,
                source_name=self.config.name,
                confidence=0.5,  # Simulation = confiance moyenne
                metadata={
                    'search_engine': 'simulated',
                    'keyword': sub
                },
                timestamp=time.time(),
                response_time=time.time() - start_time
            )
            results.append(result)
        
        return results
    
    def get_source_info(self) -> Dict:
        return {
            'name': 'Search Engines',
            'description': 'Enumeration via search engines (simulated)',
            'reliability': 'Low',
            'speed': 'Medium',
            'coverage': 'Limited'
        }

class HackerTargetSource(EnumerationSource):
    """Source d'énumération via HackerTarget API."""
    
    def __init__(self, config: SourceConfig = None):
        if config is None:
            config = SourceConfig(
                name="hackertarget",
                timeout=15.0,
                rate_limit=2.0,  # Rate limiting strict
                max_retries=2
            )
        super().__init__(config)
    
    async def enumerate(self, domain: str) -> List[EnumerationResult]:
        """Énumère via HackerTarget API."""
        results = []
        start_time = time.time()
        
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
            
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.config.timeout)) as session:
                async with session.get(url) as response:
                    if response.status == 200 and response.text:
                        lines = response.text.strip().split('\n')
                        
                        for line in lines:
                            if ',' in line:
                                subdomain = line.split(',')[0].strip()
                                if subdomain and domain in subdomain:
                                    result = EnumerationResult(
                                        subdomain=subdomain,
                                        source_name=self.config.name,
                                        confidence=0.6,  # API tierce = confiance moyenne
                                        metadata={
                                            'api': 'hackertarget',
                                            'raw_line': line
                                        },
                                        timestamp=time.time(),
                                        response_time=time.time() - start_time
                                    )
                                    results.append(result)
        
        except Exception as e:
            self.errors.append(f"HackerTarget enumeration failed: {str(e)}")
        
        return results
    
    def get_source_info(self) -> Dict:
        return {
            'name': 'HackerTarget API',
            'description': 'Enumeration via HackerTarget API',
            'reliability': 'Medium',
            'speed': 'Fast',
            'coverage': 'Good'
        }

class CustomWordlistSource(EnumerationSource):
    """Source d'énumération avec wordlist personnalisée."""
    
    def __init__(self, wordlist: List[str], config: SourceConfig = None):
        if config is None:
            config = SourceConfig(
                name="custom_wordlist",
                timeout=5.0,
                rate_limit=0.1,
                max_retries=1,
                custom_params={
                    'wordlist': wordlist,
                    'max_concurrent': 15
                }
            )
        else:
            config.custom_params['wordlist'] = wordlist
        
        super().__init__(config)
    
    async def enumerate(self, domain: str) -> List[EnumerationResult]:
        """Énumère avec une wordlist personnalisée."""
        results = []
        wordlist = self.config.custom_params.get('wordlist', [])
        max_concurrent = self.config.custom_params.get('max_concurrent', 15)
        
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def check_subdomain(word: str) -> Optional[EnumerationResult]:
            async with semaphore:
                subdomain = f"{word}.{domain}"
                start_time = time.time()
                
                try:
                    resolver = dns.resolver.Resolver()
                    resolver.timeout = 2.0
                    answers = resolver.resolve(subdomain, 'A')
                    
                    if answers:
                        result = EnumerationResult(
                            subdomain=subdomain,
                            source_name=self.config.name,
                            confidence=0.7,
                            metadata={
                                'ip': str(answers[0]),
                                'word': word,
                                'wordlist_size': len(wordlist)
                            },
                            timestamp=time.time(),
                            response_time=time.time() - start_time
                        )
                        return result
                
                except Exception:
                    pass
                
                await asyncio.sleep(self.config.rate_limit)
                return None
        
        # Exécution parallèle
        tasks = [check_subdomain(word) for word in wordlist]
        subdomain_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in subdomain_results:
            if isinstance(result, EnumerationResult):
                results.append(result)
        
        return results
    
    def get_source_info(self) -> Dict:
        return {
            'name': 'Custom Wordlist',
            'description': f'Enumeration with custom wordlist ({len(self.config.custom_params.get("wordlist", []))} words)',
            'reliability': 'Medium',
            'speed': 'Slow',
            'coverage': 'Custom'
        } 