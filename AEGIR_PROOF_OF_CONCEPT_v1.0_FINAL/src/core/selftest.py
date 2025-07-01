"""
Tests unitaires réutilisables pour le module d'énumération d'Aegir.
Développé par Antoine Kojfer (JAK)

Utilisation :
    from src.core import selftest
    selftest.test_engine_initialization()
    # etc.

Chaque fonction lève AssertionError en cas d'échec.
"""

from src.core.enumeration_engine import EnumerationEngine
from src.core.plugins import SourceConfig, EnumerationResult

# --- Tests pour le moteur d'énumération ---
def test_engine_initialization():
    """Vérifie l'initialisation du moteur d'énumération."""
    engine = EnumerationEngine()
    assert engine is not None
    assert hasattr(engine, 'sources')
    assert hasattr(engine, 'config')

def test_default_config():
    """Vérifie la configuration par défaut du moteur."""
    engine = EnumerationEngine()
    config = engine.get_default_config()
    assert 'sources' in config
    assert 'scoring' in config
    assert 'output' in config
    sources = config['sources']
    assert 'certificate_transparency' in sources
    assert 'dns_brute_force' in sources
    assert 'search_engines' in sources
    assert 'hackertarget' in sources

def test_scoring_configs():
    """Vérifie la présence des paramètres de scoring dans la config."""
    engine = EnumerationEngine()
    config = engine.get_default_config()
    scoring = config['scoring']
    assert 'min_confidence' in scoring
    assert 'min_sources' in scoring
    assert 'confidence_weight' in scoring
    assert 'source_count_weight' in scoring

# --- Tests pour la configuration des sources ---
def test_source_config_creation():
    """Vérifie la création d'une configuration de source."""
    config = SourceConfig(
        name="test_source",
        timeout=10.0,
        rate_limit=0.1,
        max_retries=3
    )
    assert config.name == "test_source"
    assert config.timeout == 10.0
    assert config.rate_limit == 0.1
    assert config.max_retries == 3
    assert config.enabled is True

def test_source_config_custom_params():
    """Vérifie la gestion des paramètres personnalisés dans SourceConfig."""
    custom_params = {"max_concurrent": 10, "wordlist": ["test"]}
    config = SourceConfig(
        name="test_source",
        custom_params=custom_params
    )
    assert config.custom_params == custom_params

# --- Tests pour les résultats d'énumération ---
def test_enumeration_result_creation():
    """Vérifie la création d'un résultat d'énumération."""
    result = EnumerationResult(
        subdomain="test.example.com",
        source_name="test_source",
        confidence=0.8,
        metadata={"test": "data"},
        timestamp=1234567890.0,
        response_time=1.5
    )
    assert result.subdomain == "test.example.com"
    assert result.source_name == "test_source"
    assert result.confidence == 0.8
    assert result.metadata == {"test": "data"}
    assert result.timestamp == 1234567890.0
    assert result.response_time == 1.5

# --- Tests asynchrones (à utiliser dans une boucle asyncio) ---
import asyncio

async def test_mock_enumeration():
    """Vérifie l'énumération avec des sources mockées (aucun appel réseau)."""
    engine = EnumerationEngine()
    # Mock des sources pour éviter les appels réseau
    engine.sources = []
    results = await engine.enumerate_domain("example.com")
    assert 'domain' in results
    assert 'subdomains' in results
    assert 'scored_subdomains' in results
    assert 'audit_log' in results
    assert 'summary' in results

async def test_aggregation_logic():
    """Vérifie la logique d'agrégation des résultats d'énumération."""
    engine = EnumerationEngine()
    test_results = {
        'source1': [
            EnumerationResult(
                subdomain="test1.example.com",
                source_name="source1",
                confidence=0.8,
                metadata={},
                timestamp=1234567890.0,
                response_time=1.0
            )
        ],
        'source2': [
            EnumerationResult(
                subdomain="test1.example.com",
                source_name="source2",
                confidence=0.9,
                metadata={},
                timestamp=1234567890.0,
                response_time=1.5
            )
        ]
    }
    aggregated = engine._aggregate_results(test_results)
    assert len(aggregated) == 1
    assert "test1.example.com" in aggregated
    results_for_subdomain = aggregated["test1.example.com"]
    assert len(results_for_subdomain) == 2

async def test_scoring_logic():
    """Vérifie la logique de scoring (tolérance flottante)."""
    engine = EnumerationEngine()
    test_aggregated = {
        "test.example.com": [
            EnumerationResult(
                subdomain="test.example.com",
                source_name="source1",
                confidence=0.8,
                metadata={},
                timestamp=1234567890.0,
                response_time=1.0
            ),
            EnumerationResult(
                subdomain="test.example.com",
                source_name="source2",
                confidence=0.9,
                metadata={},
                timestamp=1234567890.0,
                response_time=1.5
            )
        ]
    }
    scored = engine._score_subdomains(test_aggregated)
    assert len(scored) == 1
    scored_subdomain = scored[0]
    assert scored_subdomain.subdomain == "test.example.com"
    assert scored_subdomain.source_count == 2
    # Tolérance flottante
    assert abs(scored_subdomain.total_confidence - 1.7) < 1e-6
    assert scored_subdomain.final_score > 0

# --- Utilitaires pour exécution manuelle ---
def run_all_sync_tests():
    """Exécute tous les tests synchrones (lève AssertionError en cas d'échec)."""
    test_engine_initialization()
    test_default_config()
    test_scoring_configs()
    test_source_config_creation()
    test_source_config_custom_params()
    test_enumeration_result_creation()
    print("[OK] Tous les tests synchrones sont passés.")

async def run_all_async_tests():
    """Exécute tous les tests asynchrones (lève AssertionError en cas d'échec)."""
    await test_mock_enumeration()
    await test_aggregation_logic()
    await test_scoring_logic()
    print("[OK] Tous les tests asynchrones sont passés.") 