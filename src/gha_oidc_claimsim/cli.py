"""Click CLI: oidc-claimsim check | matrix | hcl-dup."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from gha_oidc_claimsim import __version__
from gha_oidc_claimsim.evaluate import evaluate_trust
from gha_oidc_claimsim.hcl_dup import format_hcl_report, scan_hcl_file
from gha_oidc_claimsim.predict import predict_claims
from gha_oidc_claimsim.report import build_payload, render_human, render_json

EXIT_ALLOW = 0
EXIT_DENY = 1
EXIT_ERROR = 2


@click.group()
@click.version_option(__version__, prog_name="oidc-claimsim")
def main() -> None:
    """Offline GitHub Actions OIDC claim simulation against IAM trust JSON."""


def _load_json(path: Path, label: str) -> dict:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise click.ClickException(f"cannot read {label} {path}: {exc}") from exc
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise click.ClickException(
            f"invalid JSON in {label} {path}: {exc.msg} (line {exc.lineno})"
        ) from exc
    if not isinstance(data, dict):
        raise click.ClickException(f"{label} {path} must be a JSON object")
    return data


def _run_check(
    workflow: Path, trust: Path, *, as_json: bool
) -> tuple[int, str]:
    ctx = _load_json(workflow, "workflow context")
    policy = _load_json(trust, "trust policy")
    try:
        claims = predict_claims(ctx)
    except (KeyError, ValueError) as exc:
        raise click.ClickException(f"invalid workflow context {workflow}: {exc}") from exc
    evaluation = evaluate_trust(claims, policy)
    payload = build_payload(
        workflow_path=str(workflow),
        trust_path=str(trust),
        claims=claims,
        evaluation=evaluation,
    )
    out = render_json(payload) if as_json else render_human(payload)
    code = EXIT_ALLOW if evaluation["allow"] else EXIT_DENY
    return code, out


@main.command("check")
@click.option(
    "--workflow",
    required=True,
    type=click.Path(path_type=Path),
    help="Workflow event context JSON (not full YAML expand).",
)
@click.option(
    "--trust",
    required=True,
    type=click.Path(path_type=Path),
    help="IAM role trust policy JSON.",
)
@click.option("--json", "as_json", is_flag=True, help="Emit machine-readable JSON.")
def check_cmd(workflow: Path, trust: Path, as_json: bool) -> None:
    """Predict OIDC sub/aud for one workflow context and evaluate against trust JSON."""
    try:
        if not workflow.is_file():
            raise click.ClickException(f"workflow file not found: {workflow}")
        if not trust.is_file():
            raise click.ClickException(f"trust file not found: {trust}")
        code, out = _run_check(workflow, trust, as_json=as_json)
    except click.ClickException as exc:
        click.echo(f"ERROR: {exc}", err=True)
        sys.exit(EXIT_ERROR)
    except Exception as exc:  # noqa: BLE001 — tool error path
        click.echo(f"ERROR: unexpected failure: {exc}", err=True)
        sys.exit(EXIT_ERROR)
    click.echo(out)
    sys.exit(code)


@main.command("matrix")
@click.option(
    "--workflows-dir",
    required=True,
    type=click.Path(path_type=Path),
    help="Directory of workflow context *.json files.",
)
@click.option(
    "--trust",
    required=True,
    type=click.Path(path_type=Path),
    help="IAM role trust policy JSON.",
)
@click.option("--json", "as_json", is_flag=True, help="Emit machine-readable JSON array.")
def matrix_cmd(workflows_dir: Path, trust: Path, as_json: bool) -> None:
    """Run check for every *.json in a directory. Exit 1 if any DENY, 2 on tool error."""
    try:
        if not workflows_dir.is_dir():
            raise click.ClickException(f"workflows dir not found: {workflows_dir}")
        if not trust.is_file():
            raise click.ClickException(f"trust file not found: {trust}")
        files = sorted(workflows_dir.glob("*.json"))
        if not files:
            raise click.ClickException(f"no *.json files in {workflows_dir}")
    except click.ClickException as exc:
        click.echo(f"ERROR: {exc}", err=True)
        sys.exit(EXIT_ERROR)

    results: list[dict] = []
    any_deny = False
    any_error = False
    human_blocks: list[str] = []

    for wf in files:
        try:
            code, out = _run_check(wf, trust, as_json=True)
            payload = json.loads(out)
            results.append(payload)
            if code == EXIT_DENY:
                any_deny = True
            verdict = payload["verdict"]
            human_blocks.append(
                f"{wf.name}: {verdict}  sub={payload['predicted_claims']['sub']}"
            )
            if not as_json:
                human_blocks.append(render_human(payload))
                human_blocks.append("")
        except click.ClickException as exc:
            any_error = True
            human_blocks.append(f"{wf.name}: ERROR — {exc}")
            results.append(
                {
                    "workflow_file": str(wf),
                    "verdict": "ERROR",
                    "error": str(exc),
                    "version": __version__,
                }
            )
        except Exception as exc:  # noqa: BLE001
            any_error = True
            human_blocks.append(f"{wf.name}: ERROR — {exc}")
            results.append(
                {
                    "workflow_file": str(wf),
                    "verdict": "ERROR",
                    "error": str(exc),
                    "version": __version__,
                }
            )

    if as_json:
        click.echo(
            json.dumps(
                {
                    "tool": "oidc-claimsim",
                    "version": __version__,
                    "trust_file": str(trust),
                    "results": results,
                    "model_caveat": "simplified IAM Condition model",
                },
                indent=2,
            )
        )
    else:
        click.echo("=== OIDC claim-sim matrix ===")
        click.echo(f"tool:  oidc-claimsim {__version__}")
        click.echo(f"trust: {trust}")
        for line in human_blocks:
            click.echo(line)

    if any_error:
        sys.exit(EXIT_ERROR)
    if any_deny:
        sys.exit(EXIT_DENY)
    sys.exit(EXIT_ALLOW)


@main.command("hcl-dup")
@click.argument("paths", nargs=-1, required=True, type=click.Path(path_type=Path))
def hcl_dup_cmd(paths: tuple[Path, ...]) -> None:
    """Optional hygiene: detect duplicate Condition/StringEquals keys in .tf files.

    Prefer tflint terraform_map_duplicate_keys in CI. Not unique IP.
    """
    exit_code = EXIT_ALLOW
    try:
        for path in paths:
            if not path.is_file():
                raise click.ClickException(f"HCL file not found: {path}")
            findings = scan_hcl_file(path)
            click.echo(format_hcl_report(path, findings))
            if findings:
                exit_code = EXIT_DENY
    except click.ClickException as exc:
        click.echo(f"ERROR: {exc}", err=True)
        sys.exit(EXIT_ERROR)
    except Exception as exc:  # noqa: BLE001
        click.echo(f"ERROR: unexpected failure: {exc}", err=True)
        sys.exit(EXIT_ERROR)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
