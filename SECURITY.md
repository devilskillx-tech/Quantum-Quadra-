# Security status

**Status: experimental; not approved for production.**

This is a reconstructed implementation rather than the historical V7.3 distribution.
It uses mandatory random 32-byte KEK, AES-GCM authenticated content and metadata,
an HMAC audit chain, explicit scope checks and local encrypted payloads.

## Limitations
- A local database and its audit log can be replaced together by an administrator.
- PostgreSQL synchronization has **not** been certified with a live server or network failures.
- Single-token FastAPI auth is insufficient for production multi-tenant deployments.
- Search decrypts documents in process; no encrypted global full-text index.
- Key storage and disaster recovery need an operational design.
- The optional embedding model is neither downloaded nor benchmarked by this project.

## Disclosure
Do not publish KEKs or client payloads in issues, logs or pull requests.
Document a reproducible test case without secrets and propose a regression test.
