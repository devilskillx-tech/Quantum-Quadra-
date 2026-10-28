# Codex working agreement — QUANTUM QUADRA 7.4

## Scope
This is a **reconstruction**, not byte-identical to historical releases. Prefer evidence-backed security improvements and regression tests to promotional version claims.

## Non-negotiable rules
1. No plaintext KEK, tokens, databases, personal payloads or DSN passwords in commits or logs.
2. Preserve fail-closed scope boundaries, payload AEAD/AAD and terminal revocations.
3. Do not bypass the explicit audit-anchor migration; an absent anchor may signal tampering.
4. Never silently overwrite a local unsynchronized change with remote content.
5. Treat PostgreSQL synchronization as experimental until live-server CI and fault-injection tests succeed.
6. Do not claim semantic retrieval performance from hashing, synthetic examples or the small benchmark fixture.
7. New schema changes require upgrade and downgrade plans, backups and regression tests.
8. Keep edits on a branch, test before committing, and leave PRs draft until reviewed.
9. Do not loosen API authentication, CORS, or scope authorization for convenience.
10. Update README, SECURITY and tests when behavior changes.

## Useful commands

```bash
python -m pip install -e '.[test,api]'
python -m pytest -q
python -m quantum_quadra selftest
python -m quantum_quadra benchmark --dataset tests/retrieval_fixture.json --k 3
```

## Architecture
- `crypto.py`: AES-GCM authenticated encryption and key wrapping.
- `store.py`: transactional SQLite memory, encrypted state and HMAC audit anchor.
- `sync.py`: Postgres ciphertext replication, conflict handling and manual DLQ.
- `search.py`: BM25 + opt-in local semantic model.
- `benchmark.py`: metric-based evaluation with scope-restricted relevance labels.
- `api.py`: authenticated single-scope FastAPI.
- `cli.py`: administrative operations with explicit confirmation.
- `tests/`: unit tests, simulated faults and opt-in real PostgreSQL tests.

## Release gate: NO AUTOMATIC MERGE
- Block merging on any known P0/P1 unresolved security or durability issue.
- `unit-tests`, `postgres-integration`, and the pre-existing `security` workflow must all pass.
- Keep PR as draft if any required integration check fails or has not run.
- The fixture benchmark is NOT evidence that a semantic model outperforms BM25.
- PostgreSQL GitHub Actions confirms basic transactions, not a production network-partition SLA.
- Protect `main` via a GitHub ruleset requiring reviews and the three checks; do not assume the README or CODEOWNERS enforce protection.


## V7.5 validation instructions for Codex
- Preserve disposable test database guardrails and run the actual PostgreSQL integration job.
- Do not present skipped live tests or the local 58-pass suite as proof of real PG resilience.
- Run real `pg_dump`/`pg_restore` in CI; never use production DSNs.
- Keep `release-gate` green and require GitHub branch ruleset before considering merge.
- Never auto-merge or bypass human review.
