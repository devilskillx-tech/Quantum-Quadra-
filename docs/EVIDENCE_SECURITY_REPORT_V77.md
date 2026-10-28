# Evidence Security Report — QUANTUM QUADRA V7.7

## Local qualification scope

- EV-01 ... EV-15: positive and negative evidence fixtures, using simulated GitHub metadata.
- TV scenarios: duplicate controls, stale proofs, run-attempt mismatch, artifact provenance, malicious ZIP path, JUnit count discrepancy, duplicate JSON, changed workflow path and forked PR.
- Collector, governance-inspector and certification-gate regression tests.
- Previous local SQLite/API/crypto/regression tests remain included.
- PostgreSQL/Toxiproxy live integration requires a configured test server; skipped locally when unavailable.

The **authoritative count** must be generated from `python -m pytest -q` at the exact candidate commit. Do not copy a prior count into a release attestation.

## Important security findings

1. `SHA-256` alone does not authenticate report origin. GitHub API binding and independently pinned workflows are required.
2. The candidate's tests cannot serve as independent proof of their own completeness. Review and independent test ownership remain necessary.
3. An active-looking ruleset is not a demonstrated blocked merge. The read-only governance inspector therefore emits `UNVERIFIABLE` pending an operational acceptance test.
4. The **trusted workflow is a bootstrap configuration**, not an already deployed trust root. It cannot be claimed effective until the protected main branch or an independent certifier repository hosts it.
5. All production decisions remain **NO-GO** until CERT-A, CERT-B, reviewer approval and operational recovery evidence are complete.

## How to reproduce

```bash
python -m pip install -e '.[test,api]'
python -m pytest -q tests/test_evidence_security.py tests/test_trusted_pipeline.py
python -m pytest -q
python -m quantum_quadra selftest
python -m scripts.github_governance_verify --output governance.json  # Requires authorized live GitHub API; fail-closed
```

## Required independent follow-up

- Activate and verify main branch ruleset through GitHub administrator.
- Add controlled blocked-merge scenario with independently reviewed, authenticated evidence.
- Deploy the trusted verifier outside the candidate's writable boundary, protect the policy and pin approved sources.
- Generate real signed provenance attestations and independently validate them.
- Run end-to-end live GitHub verification against approved candidate SHA and artifacts.
