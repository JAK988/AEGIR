"""
Moteur d'énumération intelligent avec scoring et audit
Orchestration des sources d'énumération avec validation croisée
"""

import asyncio
import time
from typing import List, Dict, Set, Optional
from dataclasses import dataclass, asdict
from collections import defaultdict
import json

from .plugins import EnumerationSource, EnumerationResult, SourceConfig
from .plugins.sources import (
    CertificateTransparencySource,
    DnsBruteForceSource,
    SearchEngineSource,
    HackerTargetSource,
    CustomWordlistSource
)

@dataclass
class ScoredSubdomain:
    """Sous-domaine avec score de pertinence."""
    subdomain: str
    sources: List[str]
    total_confidence: float
    source_count: int
    metadata: Dict
    final_score: float

@dataclass
class EnumerationAudit:
    """Log d'audit complet de l'énumération."""
    domain: str
    start_time: float
    end_time: float
    total_duration: float
    
    # Sources utilisées
    sources_configured: List[Dict]
    sources_enabled: List[str]
    sources_failed: List[str]
    
    # Résultats par source
    results_by_source: Dict[str, List[Dict]]
    source_stats: Dict[str, Dict]
    
    # Scoring et validation
    raw_subdomains: List[str]
    scored_subdomains: List[Dict]
    final_subdomains: List[str]
    
    # Métriques
    total_subdomains_found: int
    unique_subdomains: int
    average_confidence: float
    sources_used: int

class EnumerationEngine:
    """Moteur d'énumération intelligent avec scoring et audit."""
    
    def __init__(self, config: Dict = None):
        """
        Initialise le moteur d'énumération.
        
        Args:
            config: Configuration des sources et paramètres
        """
        self.config = config or self.get_default_config()
        self.sources = []
        self.audit_log = None
        self.setup_sources()
    
    def get_default_config(self) -> Dict:
        """Configuration par défaut du moteur."""
        return {
            'sources': {
                'certificate_transparency': {
                    'enabled': True,
                    'timeout': 15.0,
                    'rate_limit': 0.2,
                    'max_retries': 2
                },
                'dns_brute_force': {
                    'enabled': True,
                    'timeout': 5.0,
                    'rate_limit': 0.1,
                    'max_retries': 1,
                    'custom_params': {
                        'max_concurrent': 20
                    }
                },
                'search_engines': {
                    'enabled': True,
                    'timeout': 10.0,
                    'rate_limit': 1.0,
                    'max_retries': 2
                },
                'hackertarget': {
                    'enabled': True,
                    'timeout': 15.0,
                    'rate_limit': 2.0,
                    'max_retries': 2
                }
            },
            'scoring': {
                'min_confidence': 0.5,
                'min_sources': 1,
                'confidence_weight': 0.6,
                'source_count_weight': 0.4
            },
            'output': {
                'include_metadata': True,
                'include_audit': True
            }
        }
    
    def setup_sources(self):
        """Configure les sources d'énumération selon la config."""
        sources_config = self.config.get('sources', {})
        
        # Certificate Transparency
        if sources_config.get('certificate_transparency', {}).get('enabled', True):
            ct_config = SourceConfig(
                name="certificate_transparency",
                **sources_config.get('certificate_transparency', {})
            )
            self.sources.append(CertificateTransparencySource(ct_config))
        
        # DNS Brute Force
        if sources_config.get('dns_brute_force', {}).get('enabled', True):
            dns_conf = sources_config.get('dns_brute_force', {})
            custom_params = dns_conf.get('custom_params', {})
            dns_config = SourceConfig(
                name="dns_brute_force",
                timeout=dns_conf.get('timeout', 5.0),
                rate_limit=dns_conf.get('rate_limit', 0.1),
                max_retries=dns_conf.get('max_retries', 1),
                custom_params=custom_params
            )
            self.sources.append(DnsBruteForceSource(dns_config))
        
        # Search Engines
        if sources_config.get('search_engines', {}).get('enabled', True):
            se_config = SourceConfig(
                name="search_engines",
                **sources_config.get('search_engines', {})
            )
            self.sources.append(SearchEngineSource(se_config))
        
        # HackerTarget
        if sources_config.get('hackertarget', {}).get('enabled', True):
            ht_config = SourceConfig(
                name="hackertarget",
                **sources_config.get('hackertarget', {})
            )
            self.sources.append(HackerTargetSource(ht_config))
    
    def add_custom_source(self, source: EnumerationSource):
        """Ajoute une source personnalisée."""
        self.sources.append(source)
    
    async def enumerate_domain(self, domain: str) -> Dict:
        """
        Énumère un domaine avec toutes les sources configurées.
        
        Args:
            domain: Domaine à énumérer
        
        Returns:
            Dict: Résultats avec scoring et audit
        """
        start_time = time.time()
        
        print(f"[+] Starting intelligent enumeration for {domain}")
        print(f"[+] Using {len(self.sources)} sources: {[s.config.name for s in self.sources]}")
        
        # 1. Énumération parallèle avec toutes les sources
        all_results = await self._run_all_sources(domain)
        
        # 2. Agrégation et déduplication
        aggregated_results = self._aggregate_results(all_results)
        
        # 3. Scoring des sous-domaines
        scored_subdomains = self._score_subdomains(aggregated_results)
        
        # 4. Filtrage final
        final_subdomains = self._filter_subdomains(scored_subdomains)
        
        # 5. Création du log d'audit
        end_time = time.time()
        self.audit_log = self._create_audit_log(
            domain, start_time, end_time, all_results, 
            aggregated_results, scored_subdomains, final_subdomains
        )
        
        # 6. Résultats finaux
        return {
            'domain': domain,
            'subdomains': final_subdomains,
            'scored_subdomains': [asdict(sd) for sd in scored_subdomains],
            'audit_log': asdict(self.audit_log),
            'summary': {
                'total_sources': len(self.sources),
                'sources_used': len([s for s in self.sources if s.results]),
                'total_subdomains_found': len(aggregated_results),
                'final_subdomains': len(final_subdomains),
                'duration': end_time - start_time,
                'average_confidence': sum(sd.final_score for sd in scored_subdomains) / len(scored_subdomains) if scored_subdomains else 0
            }
        }
    
    async def _run_all_sources(self, domain: str) -> Dict[str, List[EnumerationResult]]:
        """Exécute toutes les sources en parallèle."""
        print(f"[+] Running {len(self.sources)} sources in parallel...")
        
        # Exécution parallèle de toutes les sources
        tasks = [source.run_with_retry(domain) for source in self.sources]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Agrégation des résultats par source
        all_results = {}
        for i, result in enumerate(results):
            source_name = self.sources[i].config.name
            
            if isinstance(result, list):
                all_results[source_name] = result
                print(f"[+] {source_name}: {len(result)} subdomains found")
            else:
                all_results[source_name] = []
                print(f"[!] {source_name}: Failed - {str(result)}")
        
        return all_results
    
    def _aggregate_results(self, all_results: Dict[str, List[EnumerationResult]]) -> Dict[str, List[EnumerationResult]]:
        """Agrège et déduplique les résultats de toutes les sources."""
        print(f"[+] Aggregating results from {len(all_results)} sources...")
        
        # Regroupement par sous-domaine
        subdomain_groups = defaultdict(list)
        
        for source_name, results in all_results.items():
            for result in results:
                subdomain_groups[result.subdomain].append(result)
        
        # Création des résultats agrégés
        aggregated = {}
        for subdomain, results in subdomain_groups.items():
            # Prendre le résultat avec la plus haute confiance
            best_result = max(results, key=lambda r: r.confidence)
            aggregated[subdomain] = results
        
        print(f"[+] Found {len(aggregated)} unique subdomains")
        return aggregated
    
    def _score_subdomains(self, aggregated_results: Dict[str, List[EnumerationResult]]) -> List[ScoredSubdomain]:
        """Score les sous-domaines selon leur pertinence."""
        print(f"[+] Scoring {len(aggregated_results)} subdomains...")
        
        scored_subdomains = []
        scoring_config = self.config.get('scoring', {})
        
        for subdomain, results in aggregated_results.items():
            # Calcul du score de confiance total
            total_confidence = sum(r.confidence for r in results)
            source_count = len(results)
            
            # Sources utilisées
            sources = [r.source_name for r in results]
            
            # Métadonnées agrégées
            metadata = {
                'sources': sources,
                'source_count': source_count,
                'total_confidence': total_confidence,
                'individual_confidences': {r.source_name: r.confidence for r in results}
            }
            
            # Score final pondéré
            confidence_weight = scoring_config.get('confidence_weight', 0.6)
            source_count_weight = scoring_config.get('source_count_weight', 0.4)
            
            confidence_score = min(total_confidence / len(self.sources), 1.0)
            source_score = min(source_count / len(self.sources), 1.0)
            
            final_score = (confidence_score * confidence_weight) + (source_score * source_count_weight)
            
            scored_subdomain = ScoredSubdomain(
                subdomain=subdomain,
                sources=sources,
                total_confidence=total_confidence,
                source_count=source_count,
                metadata=metadata,
                final_score=final_score
            )
            
            scored_subdomains.append(scored_subdomain)
        
        # Tri par score décroissant
        scored_subdomains.sort(key=lambda x: x.final_score, reverse=True)
        
        return scored_subdomains
    
    def _filter_subdomains(self, scored_subdomains: List[ScoredSubdomain]) -> List[str]:
        """Filtre les sous-domaines selon les critères de scoring."""
        scoring_config = self.config.get('scoring', {})
        min_confidence = scoring_config.get('min_confidence', 0.5)
        min_sources = scoring_config.get('min_sources', 1)
        
        filtered = []
        for scored in scored_subdomains:
            if (scored.final_score >= min_confidence and 
                scored.source_count >= min_sources):
                filtered.append(scored.subdomain)
        
        print(f"[+] Filtered to {len(filtered)} high-confidence subdomains")
        return filtered
    
    def _create_audit_log(self, domain: str, start_time: float, end_time: float,
                         all_results: Dict, aggregated_results: Dict,
                         scored_subdomains: List[ScoredSubdomain],
                         final_subdomains: List[str]) -> EnumerationAudit:
        """Crée le log d'audit complet."""
        
        # Sources configurées et utilisées
        sources_configured = [asdict(s.config) for s in self.sources]
        sources_enabled = [s.config.name for s in self.sources if s.config.enabled]
        sources_failed = [name for name, results in all_results.items() if not results]
        
        # Résultats par source
        results_by_source = {}
        source_stats = {}
        
        for source in self.sources:
            source_name = source.config.name
            results_by_source[source_name] = [asdict(r) for r in all_results.get(source_name, [])]
            source_stats[source_name] = source.get_stats()
        
        # Métriques
        total_subdomains_found = sum(len(results) for results in all_results.values())
        unique_subdomains = len(aggregated_results)
        average_confidence = sum(sd.final_score for sd in scored_subdomains) / len(scored_subdomains) if scored_subdomains else 0
        sources_used = len([s for s in self.sources if s.results])
        
        return EnumerationAudit(
            domain=domain,
            start_time=start_time,
            end_time=end_time,
            total_duration=end_time - start_time,
            sources_configured=sources_configured,
            sources_enabled=sources_enabled,
            sources_failed=sources_failed,
            results_by_source=results_by_source,
            source_stats=source_stats,
            raw_subdomains=list(aggregated_results.keys()),
            scored_subdomains=[asdict(sd) for sd in scored_subdomains],
            final_subdomains=final_subdomains,
            total_subdomains_found=total_subdomains_found,
            unique_subdomains=unique_subdomains,
            average_confidence=average_confidence,
            sources_used=sources_used
        )
    
    def export_audit_log(self, filepath: str):
        """Exporte le log d'audit en JSON."""
        if self.audit_log:
            with open(filepath, 'w') as f:
                json.dump(asdict(self.audit_log), f, indent=2)
            print(f"[+] Audit log exported to {filepath}")
    
    def print_summary(self):
        """Affiche un résumé de l'énumération."""
        if not self.audit_log:
            print("[!] No audit log available")
            return
        
        print("\n" + "="*60)
        print("🔍 ENUMERATION SUMMARY")
        print("="*60)
        print(f"🎯 Domain: {self.audit_log.domain}")
        print(f"⏱️  Duration: {self.audit_log.total_duration:.2f} seconds")
        print(f"📊 Sources Used: {self.audit_log.sources_used}/{len(self.sources)}")
        print(f"🔍 Total Subdomains Found: {self.audit_log.total_subdomains_found}")
        print(f"✅ Unique Subdomains: {self.audit_log.unique_subdomains}")
        print(f"🎯 Final Subdomains: {len(self.audit_log.final_subdomains)}")
        print(f"📈 Average Confidence: {self.audit_log.average_confidence:.2f}")
        
        if self.audit_log.sources_failed:
            print(f"❌ Failed Sources: {', '.join(self.audit_log.sources_failed)}")
        
        print("\n📊 SOURCE BREAKDOWN:")
        for source_name, stats in self.audit_log.source_stats.items():
            if stats['enabled']:
                subdomains_found = len(self.audit_log.results_by_source.get(source_name, []))
                print(f"  • {source_name}: {subdomains_found} subdomains")
        
        print("="*60) 