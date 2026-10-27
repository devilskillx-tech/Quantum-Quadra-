# Codex — QUANTUM QUADRA

## Mission
Maintain a security-focused **reconstruction** of QUANTUM QUADRA V7.3.
This repository is NOT a bit-for-bit copy of the earlier V7.3 artifact.

## Rules for Codex
1. Never commit secrets, `QUADRA_KEK`, `QUADRA_API_TOKEN`, local databases or decrypted payloads.
2. Preserve strict `scope_id` isolation in all write, read, recall, sync and admin paths.
3. Fail closed for invalid GCM tags, missing DEKs, invalid revisions and status tampering.
4. Keep PostgreSQL replication labelled *experimental* until tested against a real server.
5. Never present BM25/hash similarity as a validated semantic AI model.
6. Use deterministic, offline-friendly unit tests. Do not download models implicitly.
7. Introduce schema migrations rather than silently changing existing database layouts.
8. Add tests for each defect, including negative / crash-injection scenarios.
9. Work on branches; require tests and review before merging into `main`.
10. Do not advertise "production ready" without an independent security audit.

## Useful commands
```bash
python -m pip install -e '.[test,api]'
python -m pytest -q
python -m quantum_quadra selftest
```

## Architecture
- `quantum_quadra/crypto.py`: AES-256-GCM, canonical JSON, wrapping and AAD.
- `quantum_quadra/store.py`: encrypted SQLite and outbox.
- `quantum_quadra/search.py`: BM25 + optional on-disk semantic model.
- `quantum_quadra/sync.py`: encrypted PostgreSQL replication (experimental).
- `quantum_quadra/api.py`: authenticated, single-scope FastAPI.
- `quantum_quadra/cli.py`: local command-line entry point.
- `tests/`: regression tests.
