# QUANTUM QUADRA — Security posture V7.4

**Experimental, not production-certified.** No real secrets are stored in this repository.

## Implemented safeguards

- KEK must be a random 32-byte value, supplied externally; no deterministic fallback.
- Content is encrypted with AES-GCM; AAD authenticates scope, cell identity, logical key, kind, creator, status, revision, key version and payload digest.
- Per-scope DEKs are wrapped under a KEK; local rotation re-encrypts cells atomically.
- Audit trail uses a keyed HMAC chain plus a locally authenticated head/length anchor.
- A missing audit anchor on an existing database fails closed; migration requires explicit operator approval.
- Scope-specific reads and authenticated FastAPI routes; sync rejects conflicting versions, scope collisions and attempts to reactivate terminal states.
- PostgreSQL sync uses encrypted payloads, remote ciphertext verification, idempotency receipts and an explicit dead-letter queue.

## Remaining risks

1. **Full rollback**: an administrator who can restore an old copy of database and all its metadata can defeat the local audit anchor. Use remote, append-only audit checkpointing.
2. **Compromised KEK**: HMAC and encrypted payload guarantees fail if the KEK is exposed; use a KMS/HSM and document recovery.
3. **Plaintext metadata**: Core stores logical keys, types and scope IDs, which may reveal sensitive information; redesign schema if this is unacceptable.
4. **Single-token API**: lacks mature multi-tenant identity, authorization policy, revocation of bearer tokens and rate limiting; not suitable for untrusted Internet.
5. **Multi-device key rotation**: remote key distributions and disaster recovery need independent validation.
6. **PostgreSQL**: tests on an ephemeral service are integration evidence, not proof of availability, failover, backup recovery or network partition tolerance in production.
7. **Search**: decrypts scope documents in process; BM25 latency scales with scope size. Optional semantic model has no validated generalization or hallucination guarantee.
8. **Legacy migrations**: explicit audit anchor migration cannot prove events missing before its execution; export/import from historical schema is not implemented.

Avoid posting real keys, DSNs containing passwords, customer payloads or local databases in issues, CI logs and pull requests.

## Merge safety
This repository does not rely on an unenforced textual promise: maintainers must configure
a GitHub branch ruleset for `main` that requires reviews and the `unit-tests`,
`postgres-integration`, and `security` status checks. Existing P0/P1 findings block merge
even when CI is green. Do not automatically merge draft PRs.

## V7.6 limits

The test-only RTO/RPO budgets are scoped to local backup availability and restored dependencies, not an end-to-end SLA. GitHub branch rules must be verified as active by an owner. A successful dry-run script does not protect the repository. No production deployment is authorized by these changes.
