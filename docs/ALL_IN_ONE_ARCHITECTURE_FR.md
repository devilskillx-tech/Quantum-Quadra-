# QUANTUM QUADRA — Édition tout-en-un V7.7.2 (prototype expérimental)

## Démarrage

```bash
python -m pip install -e '.[test,api]'
python quadra_all.py doctor
python quadra_all.py selftest
python quadra_all.py demo-rollback
python quadra_all.py verify-formal
python quadra_all.py test
python quadra_all.py core --help
```

Le lanceur `quadra_all.py` donne accès aux commandes de contrôle ci-dessus et, via `core`, aux commandes QUANTUM QUADRA existantes : mémoire chiffrée SQLite, recherche, agents consultatifs, API et synchronisation PostgreSQL. Ex. `python quadra_all.py core --db /chemin/edge.db status`. Certaines opérations nécessitent des clés et variables d'environnement ; consulter le README original et SECURITY.md.

## Modules réunis

- `quantum_quadra/store.py`, `crypto.py`, `search.py`, `sync.py`, `recovery.py` : cœur mémoires Edge/Core, chiffrement et récupération (reconstruction de source antérieure).
- `quantum_quadra/agents.py`, `remediation_advisor.py` : agents IA consultatifs, sans GO ni élévation de permissions.
- `scripts/evidence_verify.py`, `separation_of_duties.py`, `github_governance_verify.py` : preuves, séparation des rôles et vérification non certifiante GitHub.
- `scripts/authority_what_if.py`, `minimum_privilege_cut.py`, `remediation_certificate_{build,verify}.py` : optimisation et certificat de conformité au modèle synthétique.
- `scripts/remediation_effective_state_verify.py`, `state_bound_certification.py` : cohérence des observations *simulées*, NO-GO sans autorité certifiante réelle.
- `quantum_quadra/revocation_anchor.py` : journal SQLite de révocations signées Ed25519 et témoin **simulé par un second fichier SQLite**, archive indépendante au niveau des fichiers, confirmation ancrée, contrôle anti-rollback et réconciliation.
- `formal/AtomicRevocation.tla` : spécification abstraite de référence (TLC non exécuté localement).
- `scripts/formal_mutation_runner.py` : explorateur Python borné, huit mutations volontairement dangereuses, contrôles de non-vacuité par contre-exemples ; **pas un équivalent de TLC**.

## Limitations importantes

**Il s'agit d'un prototype local, pas d'une intégration en production.** Le témoin « externe » est simulé avec un deuxième fichier sur la même machine. Les clés Ed25519 sont générées en mémoire pour les tests ; aucune gestion HSM/KMS, rotation attestée, haute disponibilité, service distant, lutte multi-opérateur contre le split-view, ni réplication indépendante n'est fournie. Une même personne possédant les deux fichiers et les clés peut réécrire les deux historiques. En production, l'ancre doit être conservée par une autorité indépendante et les décisions CERT-E recontrôlées auprès d'une source GitHub administrative authentifiée.

Le module de révocation de certificats n'est **pas** encore branché aux contrôles de chaque opération de lecture mémoire du cœur `QuadraStore`; l'ancien cœur fonctionne indépendamment. L'API du registre n'expose pas de révocation administrative autorisée : le prototype suppose des appels internes déjà autorisés et ne doit pas être exposé à des utilisateurs non fiables. Les crash tests PostgreSQL/Toxiproxy existants sont conservés, mais ne testent **pas** ce nouveau registre de révocations de bout en bout.

Le contrôle `revocation-model-tests` ajouté au `release-gate` candidat vérifie le programme Python et les mutations abstraites ; il **n'effectue pas** TLC, ne garantit pas l'état administratif réel de GitHub et n'autorise pas de fusion. Les précédents rulesets `main` n'étaient pas confirmés actifs ; les droits effectifs et l'approbation indépendante restent nécessaires.

**Verdict : NO-GO production.**
