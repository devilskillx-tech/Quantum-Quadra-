# QUANTUM QUADRA V7.7 — Evidence Trust Core: threat model

**Maturity: prototype; independently verified production certification NOT achieved.**

## Assets and boundaries

1. Candidate PR commit, candidate CI jobs and uploaded artifacts: **untrusted**.
2. GitHub API responses, requested with a read-only token: authoritative for GitHub's *observed* metadata, not a cryptographic attestation that a test is correct.
3. Externally approved policy (SHA, PR, control list, workflow Git-blob SHA): **trusted only if reviewed and maintained outside the candidate's writable tree**.
4. Trusted verifier code: must be reviewed and executed at a pinned SHA from a protected default branch or, preferably, a separate protected certification repository.
5. Repository ruleset, access exceptions and test of merge-block enforcement: governance evidence, **not** represented by a workflow's claim of successful tests.

## Threats

- Fake `PASS` string, modified JUnit/JSON after CI, replay from previous SHA/PR, wrong run/job IDs, partial workflow, skipped tests.
- Substitution of GitHub artifacts, zip bombs, path traversal, suspicious XML entities, duplicate JSON keys, nonfinite numeric values, misleading RTO/RPO counts.
- Code changes that weaken the candidate's own tests, workflow configuration, or verifier.
- Unapproved bypass actors/admin permissions; branch settings appearing in Git but not actually activated.
- GitHub API unavailable or incomplete, expired artifacts, insufficient permissions or failed run.
- Redirect to external artifact storage: never forward the GitHub Authorization header to another host.

## Mitigations implemented

- Schema and strict field allowlists, canonical SHA formats, duplicate detection, JUnit case count verification and full mandatory control coverage.
- Live lookup of PR HEAD, runs, jobs, artifacts and trusted workflow blob SHA; compare the downloaded bytes to the digest in the candidate manifest.
- Redaction of bearer tokens from cross-origin redirects, bounded artifact download/decompression, no extraction/execution of candidate ZIP contents.
- Trusted workflow blueprint checked out at `${{ github.sha }}` from protected `main`, with read-only permissions. **It cannot provide independent trust before its own source and branch rules are protected.**
- Live read-only ruleset inspector returns `UNVERIFIABLE` even for apparently compliant settings until an independently verified blocked-merge test exists.
- `certification_gate.py` CLI re-fetches evidence and governance rather than trusting an arbitrary local `VERIFIED` JSON file.

## Explicit limitations and open P0 work

- A GitHub-hosted artifact plus SHA does not cryptographically attest execution semantics or truth of test assertions. A candidate could modify its tests to make them less meaningful; pinned workflows and independent review are necessary, and independent test implementations are preferable.
- GitHub API does not by itself prove an attempted non-compliant merge was blocked. Independent operational acceptance test and effective branch ruleset audit are required for CERT-A.
- `QUADRA_EVIDENCE_POLICY_B64` must be approved and maintained outside candidate modifications. The example workflow does not self-authorize this policy.
- Full GitHub artifact attestations / OIDC identity validation and immutable external audit witness are **not implemented**.
- Current trust tests use mock GitHub responses; they are not live GitHub verification.
- PostgreSQL recovery objectives were previously tested in CI under controlled scenarios; they are not RTO/RPO production SLAs.
- Full run pagination is bounded to 100 jobs/artifacts; larger runs are refused.

## Result meanings

`VERIFIED` = GitHub observed metadata/artifact checks passed under supplied trusted policy, **not** a production certification.
`UNVERIFIABLE` = authoritative source unavailable / mandatory governance evidence missing.
`REJECTED` = supplied evidence malformed, contradictory, stale or altered.
`TECHNICAL_PASS` = allowed only after independent CERT-A and CERT-B; not produced by this prototype absent complete governance evidence.
`GO` = requires human authorization and effective governance, not produced automatically.
