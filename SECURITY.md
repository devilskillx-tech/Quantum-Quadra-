# Quantum Quadra — Security policy

## Status
This repository is currently a **public bootstrap**. Do not commit non-public architecture, private prompts, data, credentials, API keys, tokens, deployment endpoints, or production configuration here.

## Reporting
Do not publish exploit details or credentials in a public issue. Use GitHub private vulnerability reporting if the repository owner enables it, or contact the owner privately.

## Operational controls (not confirmed as enabled)
1. Change repository visibility to **Private** in Settings → General → Danger Zone if confidentiality is required.
2. Enable two-factor authentication on the GitHub account and review authorized apps.
3. In Settings → Actions → General, restrict workflow permissions to **Read repository contents**; require approval for third-party workflows as appropriate.
4. Configure a branch ruleset for main: require pull requests and passing checks, restrict direct pushes and force pushes, and require review.
5. Enable available secret scanning, push protection, dependency alerts, and private vulnerability reporting.
6. Store secrets in GitHub Actions secrets or an approved secret manager; prefer short-lived OIDC credentials when a deployment is later approved.
7. Keep STOP/default-deny at every execution boundary. A policy function or unit test alone is not enforcement.

## Boundaries
The accompanying workflow has read-only GitHub token permissions, no secrets, no deployments, no external service access, and runs only static security checks. Pattern-based scans are incomplete; they do not guarantee the absence of secrets.

**Do not publish the private Quantum Quadra architecture until the repository's actual visibility and access controls have been independently verified.**
