# QUANTUM QUADRA V7.7 — Séparation effective des pouvoirs

**État : modèle implémenté ; droits GitHub réels non audités, conclusion UNVERIFIABLE/NO-GO.** Un simple nom d'utilisateur différent n'établit pas une indépendance effective.

Le moteur `scripts/separation_of_duties.py` étend les permissions directes par les droits des groupes, rattache les comptes à un `human_id` et contrôle huit fonctions : auteur, producteur des preuves, mainteneurs du vérificateur, de la politique et du workflow protégé, relecteur, autorisateur de déploiement et administrateur rulesets.

## Invariants testés

- Aucun auteur ou producteur de preuves ne doit disposer de droits de modification du vérificateur, de la politique, des workflows, des rulesets, de bypass, d'approbation ou de déploiement.
- Aucun relecteur ou autorisateur ne peut lui-même modifier les mécanismes de confiance ou les permissions nécessaires à leur protection.
- Le cumul non contrôlé de plusieurs plans de confiance (`verifier_write`, `policy_write`, `trusted_workflow_write`, `ruleset_admin`) par une même personne est bloquant.
- Le relecteur et l'autorisateur de déploiement sont des personnes distinctes ; une même personne disposant de plusieurs comptes est traitée comme une seule identité.
- Les droits hérités des groupes, les privilèges de bypass et les rôles service-à-la-place-d'humain sont pris en compte.
- Schéma, ensembles de droits, assignations, dépôt et SHA candidat sont vérifiés strictement.

## Utilisation

```bash
python -m scripts.separation_of_duties --snapshot /chemin-protege/inventaire.json --output /chemin-protege/sod.json
```

Même sans conflit détecté, le résultat est **`UNVERIFIABLE` avec `PASS_UNATTESTED`**, exit code non nul. L'analyse d'un fichier JSON local ne garantit ni la provenance des droits ni le rattachement réel des comptes à des personnes. En cas de conflit : `NO-GO`.

Une certification effective demande : inventaire complet des droits GitHub (y compris administrateurs, bots, teams, propriétaires et délégations) récupéré hors branche candidate depuis une identité auditrice, correspondance d'identités humaines attestée, ruleset actif vérifié, scénario de fusion non conforme bloqué, vérificateur issu d'une source protégée, revue indépendante et attestation du dossier rattachée au SHA et au périmètre.

Le `certification_gate` refuse par défaut toute absence d'attestation SoD indépendante. L'ajout de la suite CI `agent-separation-tests` sert de contrôle de régression **et ne remplace pas** cet audit extérieur.
