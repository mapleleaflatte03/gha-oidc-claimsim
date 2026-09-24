"""SPEC §H acceptance cases 1–10 + tool-error exit 2. No network / no AWS."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from gha_oidc_claimsim import __version__
from gha_oidc_claimsim.cli import main


def _check(runner: CliRunner, workflow: Path, trust: Path, *extra: str):
    return runner.invoke(
        main,
        ["check", "--workflow", str(workflow), "--trust", str(trust), *extra],
        catch_exceptions=False,
    )


def test_01_push_main_branch_pinned_allow(workflows_dir, trust_dir):
    runner = CliRunner()
    result = _check(
        runner,
        workflows_dir / "push-main.json",
        trust_dir / "branch-pinned-main.json",
    )
    assert result.exit_code == 0, result.output
    assert "VERDICT:  ALLOW" in result.output
    assert "repo:acme/payments:ref:refs/heads/main" in result.output


def test_02_pull_request_branch_pinned_deny_so_class(workflows_dir, trust_dir):
    """Critical SO-class: PR sub ≠ ref:refs/heads/main → DENY exit 1."""
    runner = CliRunner()
    result = _check(
        runner,
        workflows_dir / "pull_request.json",
        trust_dir / "branch-pinned-main.json",
    )
    assert result.exit_code == 1, result.output
    assert "VERDICT:  DENY" in result.output
    assert "repo:acme/payments:pull_request" in result.output
    assert "FAIL" in result.output


def test_03_pull_request_repo_wildcard_allow(workflows_dir, trust_dir):
    runner = CliRunner()
    result = _check(
        runner,
        workflows_dir / "pull_request.json",
        trust_dir / "repo-wildcard.json",
    )
    assert result.exit_code == 0, result.output
    assert "VERDICT:  ALLOW" in result.output


def test_04_pull_request_pr_and_main_allow(workflows_dir, trust_dir):
    runner = CliRunner()
    result = _check(
        runner,
        workflows_dir / "pull_request.json",
        trust_dir / "pr-and-main.json",
    )
    assert result.exit_code == 0, result.output
    assert "VERDICT:  ALLOW" in result.output


def test_05_workflow_dispatch_branch_pinned_allow(workflows_dir, trust_dir):
    runner = CliRunner()
    result = _check(
        runner,
        workflows_dir / "workflow_dispatch-main.json",
        trust_dir / "branch-pinned-main.json",
    )
    assert result.exit_code == 0, result.output
    assert "VERDICT:  ALLOW" in result.output


def test_06_hcl_duplicate_fail(hcl_dir):
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["hcl-dup", str(hcl_dir / "oidc-role-duplicate-stringequals.tf")],
        catch_exceptions=False,
    )
    assert result.exit_code == 1, result.output
    assert "FAIL" in result.output
    assert "StringEquals" in result.output


def test_07_hcl_clean_pass(hcl_dir):
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["hcl-dup", str(hcl_dir / "oidc-role-clean.tf")],
        catch_exceptions=False,
    )
    assert result.exit_code == 0, result.output
    assert "PASS" in result.output


def test_08_empty_condition_deny(workflows_dir, trust_dir):
    runner = CliRunner()
    result = _check(
        runner,
        workflows_dir / "push-main.json",
        trust_dir / "empty-condition.json",
    )
    assert result.exit_code == 1, result.output
    assert "VERDICT:  DENY" in result.output
    assert "empty Condition" in result.output or "Condition" in result.output


def test_09_unmodeled_operator_fail_closed(workflows_dir, trust_dir):
    runner = CliRunner()
    result = _check(
        runner,
        workflows_dir / "push-main.json",
        trust_dir / "unmodeled-operator.json",
    )
    assert result.exit_code == 1, result.output
    assert "VERDICT:  DENY" in result.output
    assert "not modeled" in result.output


def test_10_json_shape_and_version(workflows_dir, trust_dir):
    runner = CliRunner()
    result = _check(
        runner,
        workflows_dir / "push-main.json",
        trust_dir / "branch-pinned-main.json",
        "--json",
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["version"] == __version__
    assert payload["verdict"] == "ALLOW"
    assert "sub" in payload["predicted_claims"]
    assert "aud" in payload["predicted_claims"]
    assert payload["model_caveat"]
    assert "simplified" in payload["model_caveat"].lower()
    assert "evaluation" in payload
    assert "statements" in payload["evaluation"]


def test_tool_error_missing_workflow(trust_dir, tmp_path):
    runner = CliRunner()
    missing = tmp_path / "nope.json"
    result = runner.invoke(
        main,
        [
            "check",
            "--workflow",
            str(missing),
            "--trust",
            str(trust_dir / "branch-pinned-main.json"),
        ],
        catch_exceptions=False,
    )
    assert result.exit_code == 2
    assert "ERROR" in result.output or "not found" in result.output.lower()


def test_tool_error_missing_trust(workflows_dir, tmp_path):
    runner = CliRunner()
    missing = tmp_path / "nope-trust.json"
    result = runner.invoke(
        main,
        [
            "check",
            "--workflow",
            str(workflows_dir / "push-main.json"),
            "--trust",
            str(missing),
        ],
        catch_exceptions=False,
    )
    assert result.exit_code == 2


def test_matrix_any_deny_exits_1(workflows_dir, trust_dir):
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "matrix",
            "--workflows-dir",
            str(workflows_dir),
            "--trust",
            str(trust_dir / "branch-pinned-main.json"),
        ],
        catch_exceptions=False,
    )
    # push + workflow_dispatch ALLOW; pull_request DENY → overall 1
    assert result.exit_code == 1, result.output
    assert "pull_request.json: DENY" in result.output
    assert "push-main.json: ALLOW" in result.output


def test_human_output_includes_caveat_and_version(workflows_dir, trust_dir):
    runner = CliRunner()
    result = _check(
        runner,
        workflows_dir / "pull_request.json",
        trust_dir / "branch-pinned-main.json",
    )
    assert __version__ in result.output
    assert "simplified IAM Condition model" in result.output
