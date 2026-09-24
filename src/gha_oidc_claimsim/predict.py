"""Predict default GitHub Actions OIDC subject and audience claims.

Authority:
https://docs.github.com/en/actions/reference/security/oidc

Default grammar only (no custom include_claim_keys templates). Environment
claim shape overrides ref/PR shapes when an environment name is set (GitHub
default for jobs that reference an environment).
"""

from __future__ import annotations

from typing import Any

PR_EVENTS = frozenset(
    {
        "pull_request",
        "pull_request_target",
        "pull_request_review",
        "pull_request_review_comment",
    }
)

DEFAULT_AUD = "sts.amazonaws.com"


def predict_claims(ctx: dict[str, Any]) -> dict[str, str]:
    """Return predicted sub/aud plus echo of event_name and repository.

    Precedence (default grammar):
    1. If ``environment`` is a non-empty string → ``repo:ORG/REPO:environment:NAME``
       (overrides ref and PR shapes per GitHub OIDC docs).
    2. Else if event is a PR-family event → ``repo:ORG/REPO:pull_request``
    3. Else → ``repo:ORG/REPO:ref:...`` (normalize ref to start with ``refs/``).
    """
    if "repository" not in ctx or not ctx["repository"]:
        raise ValueError("workflow context missing required field: repository")

    repo = str(ctx["repository"])
    event = str(ctx.get("event_name") or "")
    ref = str(ctx.get("ref") or "")
    env = ctx.get("environment")
    # Treat null / empty as unset
    if env is not None and str(env).strip() == "":
        env = None

    if env:
        sub = f"repo:{repo}:environment:{env}"
    elif event in PR_EVENTS:
        sub = f"repo:{repo}:pull_request"
    else:
        if ref and not ref.startswith("refs/"):
            ref = f"refs/heads/{ref}"
        if not ref:
            raise ValueError(
                "workflow context missing ref for non-PR / non-environment event"
            )
        sub = f"repo:{repo}:ref:{ref}"

    aud = ctx.get("audience") or DEFAULT_AUD
    return {
        "sub": sub,
        "aud": str(aud),
        "event_name": event,
        "repository": repo,
    }
