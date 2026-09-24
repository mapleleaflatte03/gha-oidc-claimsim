# Changelog

## 0.1.0-rc.2 — 2026-09-24

Remediation / polish RC after QG-003 B1 (CI) and QG-004 non-blocking notes.

- Enabled GitHub Actions: installed `.github/workflows/ci.yml` (from `ci/github-actions-ci.yml`) via GitHub UI — OAuth push lacked `workflow` scope
- Green CI on Python 3.10 + 3.12 (push to `main`)
- README CI section updated to match live Actions (honesty)
- Version strings aligned to `0.1.0-rc.2` (`pyproject.toml`, CLI `__version__`, README)
- **Still not published to PyPI** — install from git; no social / no MEASURE invent

## 0.1.0-rc.1 — 2026-09-24

Initial release candidate.

- CLI: `oidc-claimsim check`, `matrix`, `hcl-dup`
- Default GitHub OIDC claim grammar (PR / environment / ref) + `aud` default `sts.amazonaws.com`
- Simplified IAM trust JSON eval: `StringEquals` / `StringLike`; empty Condition DENY; unmodeled ops fail-closed
- Exit codes: `0` ALLOW · `1` DENY · `2` tool/config error
- Human + `--json` reports with tool version and “simplified IAM Condition model” caveat
- Fixtures + pytest acceptance (SPEC §H cases; no network / no AWS)
- Optional HCL duplicate Condition key hygiene (prefer tflint; not unique IP)
- Docs: honest residual table vs Checkov / tflint / ToB semgrep / Rezonate / Access Analyzer / AWS Jun-2025
- License: Apache-2.0
- **Not published to PyPI** for this RC — install from git
