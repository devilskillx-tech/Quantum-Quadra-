# Rapport VRC / MPC V7.7

**Prototype**: moteur de plans de retrait de privilèges, simulation déterministe, certificat VRC et revérification indépendante du modèle. Tests de sécurité de modèle uniquement, sans infrastructure GitHub authentifiée ni administration de permissions.

## Conditions de validation locale

- Toutes les données et identités de tests sont synthétiques.
- Tests de falsification, politique remplacée, ancien SHA, plan fictif, conflit d'identités, quorum, capacité de restauration supprimée, graphes de groupes imbriqués et limites d'optimisation.
- L'agent d'explication IA ne peut écrire, modifier ni donner GO.
- Le job `remediation-certificate-tests` doit réussir; le `release-gate` candidat en dépend. Ce job reste sous contrôle du candidat et n'est **pas** une certification indépendante.

## Certification

**NO-GO** jusqu'à activation administrative de la protection de `main`, attestation des droits effectifs, vérificateur protégé et approbation indépendante. La certification des permissions **après application** n'est pas implémentée en production.
