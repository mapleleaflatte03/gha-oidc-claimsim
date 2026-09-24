# gha-oidc-claimsim

Offline **GitHub Actions → AWS IAM OIDC** claim simulation CLI.

Predict default OIDC `sub` / `aud` for a workflow **event context JSON**, evaluate against an IAM role **trust policy JSON**, and print **ALLOW** or **DENY** with per-condition reasons — no STS, no AWS credentials, no network.

**Version:** `0.1.0-rc.2` (release candidate)

**Current RC:** [v0.1.0-rc.2](https://github.com/mapleleaflatte03/gha-oidc-claimsim/releases/tag/v0.1.0-rc.2) — install from git for this RC; **not on PyPI**.

CLI entrypoint: `oidc-claimsim`

## Who this is for

Platform / security / CI owners wiring **GitHub Actions → AWS** via OIDC (`token.actions.githubusercontent.com`) who need to catch **event-type claim mismatches** before merge — especially the Stack Overflow class where a trust policy pinned to `repo:ORG/REPO:ref:refs/heads/main` **DENYs** `pull_request` jobs whose default `sub` is `repo:ORG/REPO:pull_request`.

## Install (this RC — from git)

```bash
git clone https://github.com/mapleleaflatte03/gha-oidc-claimsim.git
cd gha-oidc-claimsim
python -m pip install -e ".[dev]"
```

PyPI publish is **not** done for this RC.

## Quickstart (PR → DENY — SO class)

```bash
# ALLOW — push to main matches branch-pinned trust
oidc-claimsim check \
  --workflow fixtures/workflows/push-main.json \
  --trust fixtures/trust-policies/branch-pinned-main.json
# expect: VERDICT ALLOW ; exit 0

# DENY — pull_request sub ≠ ref:refs/heads/main
oidc-claimsim check \
  --workflow fixtures/workflows/pull_request.json \
  --trust fixtures/trust-policies/branch-pinned-main.json
# expect: VERDICT DENY ; sub=repo:acme/payments:pull_request ; exit 1

# Machine-readable
oidc-claimsim check \
  --workflow fixtures/workflows/pull_request.json \
  --trust fixtures/trust-policies/branch-pinned-main.json \
  --json
```

Matrix over a directory of contexts:

```bash
oidc-claimsim matrix \
  --workflows-dir fixtures/workflows \
  --trust fixtures/trust-policies/branch-pinned-main.json
```

Optional HCL hygiene (see below):

```bash
oidc-claimsim hcl-dup fixtures/hcl/oidc-role-duplicate-stringequals.tf
```

## Exit codes

| Code | Meaning |
|-----:|---------|
| 0 | ALLOW (predicted claims satisfy ≥1 modeled Allow statement) |
| 1 | DENY (actionable — trust would reject this event’s claims) / HCL dup found |
| 2 | Tool/config error (missing file, invalid JSON, bad args) |

Migration note vs Gate C prototype scripts: prototype used `0` ALLOW / `2` DENY. This product normalizes to **0 / 1 / 2** so CI can treat DENY as an actionable failure.

## Claim prediction (default grammar)

Authority: [GitHub OIDC](https://docs.github.com/en/actions/reference/security/oidc), [Configuring OIDC in AWS](https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/configuring-openid-connect-in-amazon-web-services).

| Condition | Predicted `sub` |
|-----------|-----------------|
| `environment` set (non-empty) | `repo:ORG/REPO:environment:NAME` (overrides ref/PR shapes) |
| PR-family events (`pull_request`, `pull_request_target`, `pull_request_review`, `pull_request_review_comment`) | `repo:ORG/REPO:pull_request` |
| else | `repo:ORG/REPO:ref:...` (ref normalized to start with `refs/`) |

Default `aud`: `sts.amazonaws.com` (override via context `audience`).

## Trust evaluation (simplified)

- Considers `Effect: Allow` + `sts:AssumeRoleWithWebIdentity`
- Models `StringEquals` / `StringLike` on `token.actions.githubusercontent.com:sub` and `:aud`
- List-valued expected values OK
- **Empty `Condition` → DENY** (+ note; AWS Jun-2025 spirit for new roles)
- **Unmodeled operators → fail-closed DENY** (+ note)
- `StringLike` via `fnmatch` — **approximate**, not bit-identical to IAM
- Human and `--json` output include caveat: **simplified IAM Condition model**

## Residual honesty (what this is / is not)

| Tool / control | What it covers | Relation to this CLI |
|----------------|----------------|----------------------|
| **Checkov CKV_AWS_358** | Missing / too-broad `sub` static lint | Different JTBD — not a replacement; we do **not** sell missing-`sub` lint as primary |
| **tflint** `terraform_map_duplicate_keys` | HCL duplicate map keys | **Prefer tflint** for HCL hygiene; our `hcl-dup` is optional convenience only |
| **Trail of Bits semgrep** `aws-oidc-role-policy-duplicate-condition` | Duplicate Condition patterns | Peer for HCL class — already absorbed |
| **Rezonate / Access Analyzer** | Live-account vulnerable role scanning | Different JTBD; requires AWS credentials — out of scope |
| **AWS Jun-2025 IdP controls** | Blocks missing-`sub` on **new/updated** roles | Does **not** kill the claim-shape wedge (PR vs `ref:`) |

## HCL duplicate-key check (optional hygiene)

```bash
oidc-claimsim hcl-dup <file.tf> [...]
```

Detects duplicate `Condition` / `StringEquals` (and sibling) keys that Terraform silently overwrites (Datadog GDS / HCSEC-2023-26 class).

**This is not unique IP.** Prefer **tflint** `terraform_map_duplicate_keys` (recommended preset) in CI. Ship `hcl-dup` only as convenience.

## Limits (v0 honesty)

- Input is **context JSON**, not automatic expansion of real `.github/workflows/*.yml`
- Simplified IAM Condition model (not full IAM)
- Default claim grammar only — no custom `include_claim_keys` templates
- Immutable subject claims for some repos after **2026-07-15** may change `sub` format — not modeled in v0 (document; opt-in later)
- Environment claim uses **environment name only** (no deeper job-permission modeling)
- No live AWS / STS / network in the default check path or unit tests
- No phone-home

## Absorption kill criteria

Stop active development if GitHub, AWS, or Checkov (or equivalent first-party / dominant scanner) ships a **supported offline/CI-native workflow-event → predicted OIDC `sub`/`aud` → evaluate against IAM trust** feature that removes the need for a third-party claim-sim CLI for the named users.

Does **not** kill on: further missing-`sub` lint alone; further live-account scanners alone; peer HCL duplicate-key coverage (already absorbed).

## CI

GitHub Actions workflow: [`.github/workflows/ci.yml`](.github/workflows/ci.yml) (same text as [`ci/github-actions-ci.yml`](ci/github-actions-ci.yml)).

- Triggers: push and pull_request to `main`
- Matrix: Python 3.10 and 3.12 — `pip install -e ".[dev]"` then `pytest -q`
- Status: https://github.com/mapleleaflatte03/gha-oidc-claimsim/actions

Local substitute: `pytest -q` (19 passed on this tree).

## License

Apache-2.0 — see [LICENSE](LICENSE).

## Security

See [SECURITY.md](SECURITY.md). Pure local evaluation; no AWS credentials required for claim-sim.
