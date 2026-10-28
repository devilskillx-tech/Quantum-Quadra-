# QUANTUM QUADRA V7.7 — Agents IA consultatifs

**Statut : candidat expérimental, non certifié pour la production.** Les agents restent en lecture seule. Ils n'écrivent pas de mémoire, ne relancent pas de synchronisation et ne déclenchent aucune restauration ou autorisation de mise en production.

| Agent | Fonction | Capacité |
|---|---|---|
| `researcher` | Recherche BM25 cloisonnée par scope | Recherche et référence des cell_id ; brouillon IA local facultatif |
| `memory_curator` | Consolidation extractive proposée | Proposition `requires_approval`, jamais de modification |
| `scope_sentinel` | Audit d'intégrité local | Inspection et blocage de recherche si audit invalide |
| `sync_sentinel` | Suivi des événements pending/DEAD | Compteurs par scope, aucun push/requeue |
| `recovery_sentinel` | Inspection de préparation de récupération | Diagnostic, aucune restauration ou mesure RTO réelle |
| `evidence_sentinel` | Rappel de conformité CERT-A/B et gouvernance | Toujours `NO_GO`, aucune certification |
| `orchestrator` | Chaîne déterministe d'agents | Vérification d'intégrité avant toute consultation |

Un modèle Ollama **local et facultatif** est utilisé uniquement par `researcher` et `memory_curator` si `use_local_ai=true` ET `QUADRA_AGENT_LOCAL_MODEL` est configuré. Endpoint IP de bouclage explicite, pas d'appel réseau vers un fournisseur tiers, pas de commande fournie par un résultat LLM, pas d'accès à un autre scope. Les contenus des cellules sont considérés comme des données non fiables, jamais comme des instructions. La sortie est systématiquement étiquetée `UNVERIFIED_LOCAL_DRAFT`.

**Confidentialité :** l'agent envoie des extraits déchiffrés au modèle local sélectionné. Ne pas activer sur données sensibles sans audit du serveur, de ses plugins éventuels et des protections de l'hôte. L'absence de réseau distant dans ce client n'est pas une garantie de confinement du serveur Ollama.

```bash
python -m pip install -e '.[test,api]'
python -m pytest -q tests/test_agents.py tests/test_separation_of_duties.py
quadra --db ./quadra.db agent-run --scope UUID_AUTORISE --agent orchestrator --query 'restauration'
# IA locale installée séparément et explicitement :
export QUADRA_AGENT_LOCAL_MODEL='qwen3:4b'
quadra --db ./quadra.db agent-run --scope UUID_AUTORISE --agent researcher --query 'restauration' --use-local-ai
```

L'exemple de modèle n'affirme ni sa disponibilité ni sa qualité : les tests utilisent une substitution déterministe, et ne testent pas l'inférence d'un modèle réel. Dans l'API, `POST /agents/run` ne peut pas modifier le scope authentifié ; les champs supplémentaires tels que `scope` et `tools` sont rejetés. Ce service n'est pas destiné à l'exposition publique sans autres protections.
