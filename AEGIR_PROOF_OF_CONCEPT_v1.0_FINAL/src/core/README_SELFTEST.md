# Aegir Selftests — Guide d'utilisation

**Développé par Antoine Kojfer (JAK)**

---

## Philosophie

- **Aucun script de test exécutable** n'est livré dans le dépôt principal.
- **Tous les tests sont des fonctions Python réutilisables** ("selftests"), importables et exécutables à la demande.
- Cette approche garantit un projet propre, maintenable, et facilement extensible, tout en conservant la valeur des tests pour l'avenir.

---

## Où trouver les selftests ?

- Module principal : `src/core/selftest.py`
- Chaque fonction de test est documentée et lève `AssertionError` en cas d'échec.
- Les tests couvrent l'énumération, la configuration, l'agrégation, le scoring, etc.

---

## Exécution des selftests

### 1. Tests synchrones
```python
from src.core import selftest
selftest.run_all_sync_tests()
```

### 2. Tests asynchrones
```python
from src.core import selftest
selftest.run_all_async_tests()
```

### 3. Exécution d'un test individuel
```python
from src.core import selftest
selftest.test_engine_initialization()
```

### 4. Exécution d'un test asynchrone individuel
```python
import asyncio
from src.core import selftest
asyncio.run(selftest.test_mock_enumeration())
```

---

## Extension : écrire vos propres selftests

- Ajoutez vos fonctions dans `src/core/selftest.py` ou dans un module dédié.
- Respectez la convention :
  - Nom explicite (`def test_nom_fonctionnalite(): ...`)
  - Docstring claire
  - Utilisez `assert` pour les vérifications
- Pour les tests asynchrones, définissez-les avec `async def` et exécutez-les avec `asyncio.run()`.

---

## Intégration dans un pipeline CI/CD (optionnel)

- Vous pouvez créer un script Python qui importe et exécute les selftests dans votre pipeline.
- Exemple :
```python
from src.core import selftest
selftest.run_all_sync_tests()
import asyncio
asyncio.run(selftest.test_mock_enumeration())
```
- En cas d'échec, une `AssertionError` sera levée et le pipeline pourra échouer.

---

## Pourquoi ce choix ?

- **Propreté du dépôt** : pas de scripts de test exécutables, pas de pollution.
- **Sécurité** : pas d'exposition de détails internes par des scripts de test autonomes.
- **Extensibilité** : facile à enrichir, à intégrer dans d'autres workflows, ou à transformer en plugins.
- **Développement** : par un expert en sécurité offensive reconnu.

---

## Ressources utiles

- [SecLists](https://github.com/danielmiessler/SecLists) — Wordlists de référence pour la sécurité offensive.
- [Pytest](https://docs.pytest.org/) — Pour inspiration sur l'écriture de tests unitaires.
- [Aegir Technical Architecture](../docs/TECHNICAL_ARCHITECTURE.md)

---

**Pour toute contribution, suivez la philosophie selftest et documentez vos ajouts !** 