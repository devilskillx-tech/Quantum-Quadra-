# QUANTUM QUADRA 7.4.0 — Codex reconstruction

> **Statut : expérimental, non certifié pour la production.** Reconstruction indépendante basée sur le code partagé dans la conversation, et non copie bit-à-bit d'une version historique. Les sources de la branche GitHub peuvent être relues, testées et modifiées dans Codex.

## Fonctionnalités

- **Sécurité des cellules** : AES-256-GCM avec DEK aléatoire par scope, KEK obligatoire de 32 octets, métadonnées et statut authentifiés par AAD, IDs UUID indépendants du contenu.
- **Stockage** : SQLite WAL, transactions atomiques, isolation logique par scope, verrou pour les lectures sur la connexion partagée ; détection d'altération et refus des statuts réactivés artificiellement.
- **Audit** : HMAC chaîné et ancre locale HMAC du nombre d'événements et du dernier hash. Détecte suppression de tête/queue *si l'ancre subsiste*. Ne résiste pas à une restauration complète de l'ancienne base ni à la compromission de la KEK.
- **Migration audit V7.3.1** : l'ancre absente fait échouer l'ouverture par défaut ; un opérateur peut effectuer une migration explicite contrôlée, après sauvegarde et vérification.
- **Récupération** : rotation des DEK par ré-encryptage atomique ; les anciennes versions sont conservées pour compatibilité, leur suppression/effacement nécessite une procédure distincte.
- **Recherche** : BM25 vérifiable, recherche par scope sur documents déchiffrés en mémoire. Mode hybride uniquement si un modèle local SentenceTransformers est explicitement fourni (ni téléchargement automatique, ni promesse de qualité).
- **Évaluation** : `quadra benchmark` mesure MRR@k, nDCG@k, rappel@k et précision@k sur des jugements de pertinence annotés.
- **Synchronisation expérimentale** : copies de blobs chiffrés vers PostgreSQL, reçus idempotents, événements réservés temporairement, validation des anciennes enveloppes, protection des versions et des révocations, dead-letter après 8 échecs et réactivation manuelle.
- **API** : FastAPI single-scope avec Bearer token. Aucun CORS permissif par défaut ; pas de multi-tenant professionnel ou limitation de débit certifiée.

## Installation

```bash
python -m pip install -e '.[test,api]'
python -m pytest -q
python -m quantum_quadra selftest
quadra generate-key
```

Conserver la clé aléatoire de 32 octets produite dans un gestionnaire de secrets. Définir localement :

```bash
export QUADRA_KEK='BASE64_ALEATOIRE_32_OCTETS'
export QUADRA_EDGE_DB='./quadra.db'
quadra init
quadra write --scope 'UUID_DU_SCOPE' --key 'règle' --payload '{"verdict":"validé"}'
quadra search --scope 'UUID_DU_SCOPE' --query 'verdict'
quadra verify
```

### API

Définir `QUADRA_API_TOKEN` (au moins 24 caractères) et `QUADRA_API_SCOPE` (UUID autorisé), puis :

```bash
quadra serve --host 127.0.0.1 --port 8000
```

Ne pas exposer directement à Internet : terminer TLS, authentification, contrôle de débit, surveillance et sauvegardes doivent être ajoutés par le déploiement.

### Passage depuis la reconstruction V7.3.1

**Sauvegarder la base, la KEK et ses métadonnées de manière indépendante.** La nouvelle ancre locale d'audit n'existait pas en 7.3.1. Une migration automatique silencieuse masquerait une éventuelle suppression de journaux :

```bash
quadra --db ./quadra.db migrate-audit-anchor --confirm-local-operator
quadra --db ./quadra.db verify
```

Cette migration vérifie la chaîne d'audit disponible, puis signe son état existant. Elle ne prouve pas que l'historique n'a jamais été altéré avant la migration. Les bases V6.x et schémas historiques ne sont **pas** automatiquement convertis.

### PostgreSQL (optionnel, à valider sur installation réelle)

```bash
python -m pip install -e '.[postgres]'
quadra sync-init --dsn 'postgresql://...' --confirm-local-operator
quadra sync-push --dsn 'postgresql://...' --scope 'UUID_DU_SCOPE'
quadra sync-pull --dsn 'postgresql://...' --scope 'UUID_DU_SCOPE'
```

Tester uniquement sur une base autorisée et isolée. En production future, utiliser une connexion TLS avec vérification d'identité du serveur (`sslmode=verify-full`) et des permissions SQL réduites. Le Core conserve **le ciphertext mais pas les clés maîtres en clair** ; il conserve néanmoins des métadonnées (scope, clé logique, type, état, importance) en clair.

Une erreur permanente de synchronisation passe en **DEAD** après huit tentatives ; l'opérateur doit examiner la cause avant toute reprise :

```bash
quadra sync-requeue-dead --scope 'UUID_DU_SCOPE' --confirm-local-operator
```

### Évaluation de la recherche

```bash
quadra benchmark --dataset tests/retrieval_fixture.json --k 3
# Mode hybride seulement avec un modèle local installé :
quadra benchmark --dataset MON_CORPUS_ANNOTE.json --mode hybrid --model-path /opt/models/embedding
```

Jeu attendu : `documents: [{"id", "scope", "text"}]`, `queries: [{"text", "scope", "relevant": ["id"]}]`. Le fixture fourni teste les métriques ; il n'est pas un benchmark de performance générale. Séparer les jeux de développement et d'évaluation, inclure des requêtes difficiles et éviter toute fuite entre scopes.

## Validation

- Suite locale : `pytest -q` (tests SQLite, API, recherche, état, audit, pannes simulées ; intégrations PostgreSQL ignorées sans DSN).
- Tests contre **PostgreSQL 16 réel** : job GitHub Actions `postgres-integration` avec un conteneur de test jetable ; le résultat CI doit être vérifié avant revendication de réussite.
- L'option `QUADRA_TEST_PG_DSN` permet d'exécuter ces tests avec un serveur de test autorisé. Ne jamais viser une base de production : l'initialisation crée des tables.
- `QUADRA_SEMANTIC_MODEL_PATH` n'est pas requis pour les tests BM25 ; aucune qualité de modèle sémantique n'est établie sans corpus annoté indépendant.

## Limites de la version

La résistance aux réécritures complètes de bases nécessite un témoin d'audit hors machine (WORM, ancre distante), un protocole multi-appareil de rotation de clés, une revue cryptographique externe, un benchmark sémantique représentatif, la gestion robuste de sauvegardes/restaurations, le contrôle d'accès SQL, et des tests de pannes réseau dans un environnement proche de la production. L'absence de ces critères interdit de qualifier cette version de « production ready ».
