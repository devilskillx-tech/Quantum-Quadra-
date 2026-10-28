# V7.7 — Verifiable Remediation Certificate / EAG-MPC (prototype sécurisé)

## Périmètre exact

Ce jalon traite **uniquement des graphes synthétiques** de permissions, après le noyau de preuve et la séparation des responsabilités V7.7. Il est **sans écriture**, n'administre pas GitHub et **ne fournit aucun GO de production**. Il ne remplace pas la vérification PostgreSQL/SQLite, CERT-A/B, les rulesets ou la revue humaine.

### Niveau 1 — `MODEL_VERIFIED`

1. Le modèle contient des principaux associés à des identités humaines confirmées *dans le jeu de données*, des groupes (y compris imbriqués), des grants directs/hérités et une politique de sécurité.
2. L'optimiseur `minimum_privilege_cut.py` recherche exhaustivement les sous-ensembles révocables dans un périmètre borné (16 droits révocables maximum). Une absence de solution donne `UNSAT`. Au-delà de la borne, il retourne `UNVERIFIABLE`, jamais une prétendue optimalité.
3. Les contraintes comprennent des **paires de capacités incompatibles** pour une même identité humaine, des capacités de continuité `all_of` et des quorum d'approbation à **personnes distinctes**. Les droits protégés ne peuvent pas être retirés.
4. Le moteur `authority_what_if.py` calcule les pouvoirs effectifs après retraits en parcourant les appartenances de groupes, recalcule les invariants et refuse de rompre les capacités critiques. **Le plan ne peut que retirer des droits**; le transfert/création n'est pas pris en charge, pour empêcher l'introduction de nouvelles délégations non modélisées.
5. Le certificat contient l'empreinte canonique du graphe, de la politique, du plan, le SHA du candidat, la provenance déclarée (`SYNTHETIC_MODEL`) et le coût revendiqué. **Une empreinte SHA-256 n'authentifie pas l'origine**.
6. `remediation_certificate_verify.py` reçoit **séparément** le graphe, la politique et le SHA attendus, recalcule les invariants, puis vérifie indépendamment la revendication d'optimalité par recherche exhaustive. Il rejette toute substitution, falsification ou incompatibilité. Un contrôle positif produit `MODEL_VERIFIED / SYNTHETIC_MODEL_ONLY`, jamais `VERIFIED` de production.

**Limite importante** : ce modèle à grants + groupes + paires de capacités + quorum est une **abstraction partielle** de GitHub. Il n'analyse pas toutes les expressions d'autorisation réelles (conditions temporelles, branch protection combinée, bypass d'applications, contrôles externes, délégations dynamiques). Par construction, **un inventaire incomplet n'est pas prouvé complet**. Aucun certificat d'autorité effective ne peut être délivré avec ce moteur seul.

### Niveau 2 — Observed State / indépendance réelle

`remediation_effective_state_verify.py` compare le graphe post-application revendiqué à la transformation autorisée et recalcule les invariants. Même si la simulation est cohérente, son verdict est uniquement `OBSERVED_MODEL_CONSISTENT`, sans autorisation. **La bibliothèque ne fournit volontairement aucun collecteur administratif réel ni aucune méthode permettant à un JSON de s'auto-attester**.

L'atteinte future de `EFFECTIVE_STATE_VERIFIED` exigerait **deux autorités distinctes** (collecte des permissions avec provenance authentifiée; attestation de revue/applications avec identité et droits confirmés), ainsi que la vérification live des rulesets, des approbations, du test de blocage et des droits indirects. Ces prérequis restent **NON DÉMONTRÉS**.

### Trois modes de travail locaux

```bash
python -m scripts.remediation_cli plan --graph graph-synthetique.json --policy politique-synthetique.json --sha aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --source-id jeu-test-001
python -m scripts.remediation_cli build --graph graph-synthetique.json --policy politique-synthetique.json --sha aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --source-id jeu-test-001 --output cert-vrc.json
python -m scripts.remediation_cli verify --graph graph-approuve-independamment.json --policy politique-approuvee-independamment.json --sha aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --source-id jeu-test-001 --certificate cert-vrc.json
```

Le dernier exemple ne signifie quelque chose que si les **fichiers d'entrée du vérificateur** sont effectivement issus d'une autorité approuvée, *hors contrôle du candidat*. Les commandes ci-dessus sont des travaux locaux d'essai et n'établissent pas ce contrôle de provenance.

### Agent IA

`quantum_quadra.remediation_advisor.explain_remediation` explique la liste de retraits et les prérequis. Il peut produire un brouillon via le modèle local optionnel déjà présent. Son résultat conserve `authorization: NONE`, `writes_performed: false` et `ai_draft_untrusted`. Il ne reçoit pas les graphes, jetons ou dossiers de preuve bruts. L'IA ne calcule pas les invariants et n'est pas autorisée à les changer.

### Points bloquants avant production

- `main`: ruleset réel **non confirmé** lors des dernières vérifications GitHub (`[]` via l'API consultée).
- Pas de vérificateur indépendant activé depuis une autorité protégée.
- Pas d'audit de permissions GitHub effectives ni de correspondance des identités humaines approuvé.
- Pas d'attestation live indépendante post-application ni de revue humaine finale.
- Aucune modification de permissions, aucun merge, aucun déploiement ne doit être effectué automatiquement.

**Verdict : `NO-GO` production.** L'état `MODEL_VERIFIED` n'est qu'un premier contrôle de cohérence mathématique.
