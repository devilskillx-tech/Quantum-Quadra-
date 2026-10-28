# QUANTUM QUADRA 7.5.0 — Codex reconstruction

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

## V7.4 release gate (current run)

**Local:** 52 tests passed, 5 live PostgreSQL tests skipped (no service available).
**CI:** must run all 5 live PostgreSQL tests against the ephemeral PostgreSQL 16 service, with zero skips.
**Blocking policy:** no merge for P0/P1 open defects; CI success is necessary but not sufficient for production.
**Limitations:** no chaos proxy / realistic multi-node partition test, no external WORM audit anchor, no independent security audit or representative semantic benchmark.


## V7.5 — Certification de résilience (candidate, pas encore validée)

- **Correctif CI** : 12 valeurs SQL pour les 12 colonnes de `quadra_core_cells`, identifié après l'échec réel PostgreSQL de V7.4.
- **Crash tests** : `tests/test_certification_unit.py` (restauration SQLite, corruption et audit), `tests/test_certification_postgres.py` (CT-03 Toxiproxy, CT-04 workers réels), en complément de 5 tests PostgreSQL antérieurs.
- **Restauration réelle** : `scripts/restore_smoke.py` réalise un snapshot SQLite avec outbox en attente, vérifie le dump/restore PostgreSQL et l'idempotence après récupération.
- **CI** : jobs `unit-tests`, `postgres-integration`, `fault-injection`, `restore-validation` et `release-gate`. La qualification CI ne représente pas une certification de production.
- **Environnement GitHub** : services PostgreSQL 16 + Toxiproxy ; les tests n'utilisent que des bases jetables synthétiques.
- **Limite de CT-03** : le test Toxiproxy simule une partition au niveau de la connexion, pas une coupure arbitraire de paquet pendant chaque instruction SQL.
- **Protection de `main`** : dans GitHub Settings > Rules > Rulesets, exiger `release-gate`, `security`, revue humaine, et empêcher les contournements. Sans ruleset effectivement activé, un job rouge n'est pas une protection de fusion.

Exécution locale :
```bash
python -m pip install -e '.[test,api]'
python -m pytest -q tests/test_certification_unit.py
# Test live : QUADRA_TEST_PG_DSN=postgresql://... pytest -q tests/test_postgres_integration.py tests/test_certification_postgres.py -k 'not ct03'
```

**No-go :** tests obligatoires ignorés en CI, rupture d'isolation, erreur d'intégrité, données perdues, ou P0/P1 non corrigés.

## V7.6 — RTO/RPO de tests et règles de fusion

Cette itération introduit des objectifs **de scénario**, non des SLO de production :
- SQLite : RTO <= 10 s à partir d'une sauvegarde cohérente déjà disponible ; RPO = 0 cellule durablement acquittée présente dans la sauvegarde.
- PostgreSQL : RTO <= 20 s à compter de la levée de la panne injectée, pour le rejeu après commit et la réhydratation d'une deuxième Edge ; RPO = 0 cellule de l'échantillon durci.
- Rapports JSON sans charges utiles via `QUADRA_RECOVERY_REPORT_DIR`; XML pytest; refus des tests obligatoires ignorés.

Les chiffres sont des **budgets exploratoires CI**. Ils ne démontrent pas un RPO temporel nul sur toutes les pannes ni une restauration opérationnelle depuis le début d'une panne longue. Un exercice SRE indépendant doit définir un RTO de service de bout en bout.

### Protection de `main`

Le script `python scripts/apply_main_ruleset.py` affiche la configuration proposée **sans modifier GitHub**. Une activation nécessite le rôle administrateur et une action explicite du propriétaire : `GITHUB_TOKEN=... python scripts/apply_main_ruleset.py --apply`. Vérifier ensuite dans Settings > Rules > Rulesets la présence effective des checks `release-gate` et `security` et de l'approbation obligatoire. Un simple fichier YAML dans le dépôt ne protège pas `main`.

**Attention :** la branche V7.6 est empilée sur V7.5 ; on ne doit pas fusionner cette PR directement dans `main` avant ses bases et leurs revues.

## V7.7 — Evidence Trust Core (experimental)

New tools under `scripts/`:

- `evidence_verify.py` validates a strict manifest against **fresh GitHub API metadata** and approved out-of-band workflow pins; only reports the limited `GITHUB_OBSERVED_EVIDENCE` scope.
- `evidence_collect.py` creates an **unverified** manifest from GitHub job and artifact IDs.
- `build_recovery_evidence.py` normalizes selected RTO/RPO measurements, rejecting missing or failed scenarios.
- `github_governance_verify.py` reads live branch rules; even compliant configuration remains `UNVERIFIABLE` pending independent blocked-merge testing.
- `certification_gate.py` re-verifies rather than accepting arbitrary local `PASS` files, and never grants production GO.

Offline tests (including fake GitHub providers):

```bash
python -m pytest -q tests/test_evidence_security.py tests/test_trusted_pipeline.py
```

Live operation requires an operator-reviewed policy outside candidate control, a read-only GitHub token and run/job/artifact IDs from the **exact** commit. See `docs/EVIDENCE_THREAT_MODEL_V77.md` and `.github/workflows/evidence-trusted.yml` for the operator-triggered trust-pipeline blueprint.

**The blueprint is NOT an active trusted pipeline or a branch ruleset.** It must run from protected `main` or, preferably, a dedicated protected certifier repository. It must not execute candidate scripts with elevated permissions. The existing V7.6 recovery tests and objectives are preserved. Production status remains NO-GO.

## V7.7 experimental agents and SoD guardrail (NOT production-certified)

New read-only specialist roles include researcher, memory curator, audit/sync/recovery sentinels and evidence sentinel, coordinated by a fixed orchestrator. Optional Ollama model inference is loopback-only and explicitly enabled. Documentation: [`docs/AGENT_ARCHITECTURE_V77.md`](docs/AGENT_ARCHITECTURE_V77.md).

The separation-of-duties checker identifies privilege overlap between developer, proof producer, verifier, policy, review and GitHub administration—including inherited grants and account aliases—on a **supplied model**. It never attests actual rights or emits `VERIFIED`. See [`docs/SEPARATION_OF_DUTIES_V77.md`](docs/SEPARATION_OF_DUTIES_V77.md). This prerequisite is fail-closed in the certification aggregator. **Production remains NO-GO** until GitHub protections, independent verifier and human governance are actually validated.
