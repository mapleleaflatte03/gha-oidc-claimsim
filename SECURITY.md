# Security Policy

## Supported versions

Report issues against the latest `main` / published RC of `gha-oidc-claimsim`.

## Reporting a vulnerability

Use GitHub security advisories on https://github.com/mapleleaflatte03/gha-oidc-claimsim (Security tab → Advisories). Do not file public issues that include live AWS account IDs, trust policies with sensitive principals, or credentials.

## Design defaults (v0)

- Pure local evaluation for claim-sim — **no AWS credentials** and **no network** required for `check` / `matrix`.
- No phone-home.
- Fail-closed on unmodeled IAM Condition operators (prefer false DENY over false ALLOW).
- Trust JSON and workflow contexts may contain account IDs — treat as sensitive-ish; do not paste into public tickets by default.
- `StringLike` matching is an `fnmatch` approximation — not a guarantee of IAM bit-identity.

## Dependencies

Direct runtime dependency: `click`. Re-check before any public RELEASE or PyPI publish (separate auth).
