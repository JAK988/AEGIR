"""
Aegir Plugin System - Architecture modulaire pour l'énumération
Interface standardisée pour les sources d'énumération de sous-domaines
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Set, Optional
from dataclasses import dataclass
import asyncio
import time

@dataclass
class EnumerationResult:
    """Résultat d'énumération d'une source."""
    subdomain: str
    source_name: str
    confidence: float  # 0-1
    metadata: Dict
    timestamp: float
    response_time: float

@dataclass
class SourceConfig:
    """Configuration d'une source d'énumération."""
    name: str
    enabled: bool = True
    timeout: float = 10.0
    rate_limit: float = 0.1
    max_retries: int = 3
    custom_params: Dict = None
    
    def __post_init__(self):
        if self.custom_params is None:
            self.custom_params = {}

class EnumerationSource(ABC):
    """Interface abstraite pour les sources d'énumération."""
    
    def __init__(self, config: SourceConfig):
        self.config = config
        self.results = []
        self.errors = []
        self.stats = {
            'start_time': 0,
            'end_time': 0,
            'total_requests': 0,
            'successful_requests': 0,
            'failed_requests': 0,
            'subdomains_found': 0
        }
    
    @abstractmethod
    async def enumerate(self, domain: str) -> List[EnumerationResult]:
        """Énumère les sous-domaines pour un domaine donné."""
        pass
    
    @abstractmethod
    def get_source_info(self) -> Dict:
        """Retourne les informations sur la source."""
        pass
    
    def update_stats(self, subdomains_found: int, response_time: float, success: bool = True):
        """Met à jour les statistiques de la source."""
        self.stats['total_requests'] += 1
        if success:
            self.stats['successful_requests'] += 1
            self.stats['subdomains_found'] += subdomains_found
        else:
            self.stats['failed_requests'] += 1
    
    def get_stats(self) -> Dict:
        """Retourne les statistiques de la source."""
        return {
            'source_name': self.config.name,
            'enabled': self.config.enabled,
            'stats': self.stats.copy(),
            'errors': self.errors.copy(),
            'results_count': len(self.results)
        }
    
    async def run_with_retry(self, domain: str) -> List[EnumerationResult]:
        """Exécute l'énumération avec retry et gestion d'erreurs."""
        self.stats['start_time'] = time.time()
        self.results = []
        self.errors = []
        
        for attempt in range(self.config.max_retries):
            try:
                start_time = time.time()
                results = await self.enumerate(domain)
                response_time = time.time() - start_time
                
                self.results = results
                self.update_stats(len(results), response_time, success=True)
                self.stats['end_time'] = time.time()
                
                return results
                
            except Exception as e:
                error_msg = f"Attempt {attempt + 1} failed: {str(e)}"
                self.errors.append(error_msg)
                
                if attempt < self.config.max_retries - 1:
                    await asyncio.sleep(self.config.rate_limit * (attempt + 1))
                else:
                    self.update_stats(0, 0, success=False)
                    self.stats['end_time'] = time.time()
                    return []
        
        return [] 