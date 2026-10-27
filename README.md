# QUANTUM QUADRA — Reconstruction source 7.3.1

> **Attention :** reconstruction indépendante d'après les extraits de code V6.x et le descriptif du projet V7.3 présents dans la conversation. **Ce n'est pas la copie bit-à-bit du livrable V7.3 antérieur.**

## Fonctions implémentées

- AES-256-GCM avec clé maître obligatoire (`QUADRA_KEK` base64 de 32 octets), DEK aléatoire par scope ; AAD authentifiant `scope_id`, identifiant, clé logique, type, statut, révision, version de clé et hash du contenu.
- Stockage SQLite WAL, identifiants UUID, révoquation irréversible dans l'API, outbox et audit local HMAC chaîné.
- Rotation DEK avec ré-encryptage dans une transaction SQLite.
- Recherche **BM25** exacte sur données déchiffrées à la volée (petits jeux seulement) et mode hybride désactivé sans modèle SentenceTransformer **déjà installé localement**.
- Consolidation **extractive** et non IA générative ; sources conservées.
- API FastAPI restreinte à un scope, authentification Bearer ; pas de CORS permissif par défaut.
- Réplication PostgreSQL chiffrée **optionnelle, non testée sur serveur réel** ; reçus d'idempotence, leasing d'outbox, contrôle de révisions, refus des clés incompatibles et protection contre écrasement de cellules locales non synchronisées.

## Installer et tester

```bash
python -m pip install -e '.[test,api]'
python -m pytest -q
quadra generate-key
```

Enregistrer la valeur retournée **en lieu sûr** comme `QUADRA_KEK`. Ne jamais remplacer par un seed déterministe.

```bash
export QUADRA_KEK='BASE64_DE_32_OCTETS'
export QUADRA_EDGE_DB='./quadra.db'
quadra init
quadra selftest
quadra status
quadra write --scope 'UUID_SCOPE' --key 'fait' --payload '{"texte":"mémoire"}'
quadra search --scope 'UUID_SCOPE' --query 'mémoire'
```

Sous Windows, définir les variables via PowerShell : `$env:QUADRA_KEK="..."`.

## API

Définir `QUADRA_API_TOKEN` (au moins 24 caractères) et `QUADRA_API_SCOPE` (UUID du scope autorisé). Démarrer `quadra serve --host 127.0.0.1 --port 8000`. Toute requête doit porter `Authorization: Bearer <token>`. Ne pas exposer le serveur directement à Internet sans TLS, protection anti-abus, et contrôles opérationnels supplémentaires.

## PostgreSQL (expérimental)

Installer `pip install -e '.[postgres]'`. Les commandes `quadra sync-init --dsn ... --confirm-local-operator`, `sync-push` et `sync-pull` demandent un serveur PostgreSQL accessible. **Aucun essai sur serveur réel n'est inclus dans cette livraison.** Ne pas traiter le schéma de réplication comme certifié. Utiliser TLS, identifiants à portée réduite, et une stratégie explicite d'amorçage des clés entre appareils (`bootstrap_scope_keys`).

## Limites connues

- Ne pas confondre 18 tests unitaires avec une certification de production.
- Le journal HMAC local révèle la modification d'entrées présentes, mais **n'empêche pas l'effacement de toute la base, sa restauration complète ou la suppression de fin de journal** ; audit WORM/ancrage distant requis.
- Les classements BM25 déchiffrent toutes les mémoires du scope et consomment O(nombre de documents) ; index chiffré dédié à concevoir pour gros volumes.
- Moteur sémantique local optionnel non benchmarké.
- Synchronisation PostgreSQL non certifiée, dont échec réseau, conflits multi-appareils et rotation de clés multi-device.
- Pas de migration automatique du schéma V6.x/V7.x historique : export + import vérifié nécessaires.
