"""Unit tests for claim prediction grammar."""

from __future__ import annotations

import pytest

from gha_oidc_claimsim.predict import predict_claims


def test_pr_event_shape():
    claims = predict_claims(
        {
            "repository": "acme/payments",
            "event_name": "pull_request",
            "ref": "refs/pull/1/merge",
            "environment": None,
        }
    )
    assert claims["sub"] == "repo:acme/payments:pull_request"
    assert claims["aud"] == "sts.amazonaws.com"


def test_environment_overrides_ref():
    claims = predict_claims(
        {
            "repository": "acme/payments",
            "event_name": "push",
            "ref": "refs/heads/main",
            "environment": "production",
        }
    )
    assert claims["sub"] == "repo:acme/payments:environment:production"


def test_ref_normalized():
    claims = predict_claims(
        {
            "repository": "acme/payments",
            "event_name": "push",
            "ref": "main",
        }
    )
    assert claims["sub"] == "repo:acme/payments:ref:refs/heads/main"


def test_custom_audience():
    claims = predict_claims(
        {
            "repository": "acme/payments",
            "event_name": "push",
            "ref": "refs/heads/main",
            "audience": "https://example.com",
        }
    )
    assert claims["aud"] == "https://example.com"


def test_missing_repository_raises():
    with pytest.raises(ValueError, match="repository"):
        predict_claims({"event_name": "push", "ref": "refs/heads/main"})
