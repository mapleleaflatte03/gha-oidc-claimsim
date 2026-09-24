"""Human and JSON report rendering for claim-sim verdicts."""

from __future__ import annotations

import json
from typing import Any

from gha_oidc_claimsim import __version__
from gha_oidc_claimsim.evaluate import MODEL_CAVEAT


def build_payload(
    *,
    workflow_path: str,
    trust_path: str,
    claims: dict[str, str],
    evaluation: dict[str, Any],
) -> dict[str, Any]:
    verdict = "ALLOW" if evaluation.get("allow") else "DENY"
    return {
        "tool": "oidc-claimsim",
        "version": __version__,
        "workflow_file": workflow_path,
        "trust_file": trust_path,
        "event_name": claims.get("event_name"),
        "repository": claims.get("repository"),
        "predicted_claims": {
            "sub": claims["sub"],
            "aud": claims["aud"],
        },
        "evaluation": {
            "allow": evaluation.get("allow"),
            "statements": evaluation.get("statements", []),
            "notes": evaluation.get("notes", []),
        },
        "verdict": verdict,
        "model_caveat": evaluation.get("model_caveat", MODEL_CAVEAT),
    }


def render_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, indent=2)


def render_human(payload: dict[str, Any]) -> str:
    claims = payload["predicted_claims"]
    lines = [
        "=== OIDC claim simulation (offline) ===",
        f"tool:     oidc-claimsim {payload['version']}",
        f"workflow: {payload['workflow_file']}",
        f"trust:    {payload['trust_file']}",
        f"event:    {payload.get('event_name')}",
        f"repo:     {payload.get('repository')}",
        f"predicted sub: {claims['sub']}",
        f"predicted aud: {claims['aud']}",
        f"VERDICT:  {payload['verdict']}",
        f"caveat:   {payload.get('model_caveat', MODEL_CAVEAT)}",
    ]
    for stmt in payload.get("evaluation", {}).get("statements", []):
        lines.append(
            f"  statement[{stmt['statement_index']}] allow={stmt['allow']}"
        )
        for c in stmt.get("checks", []):
            if "matched" in c:
                mark = "PASS" if c["matched"] else "FAIL"
                lines.append(f"    [{mark}] {c['op']} {c['key']}")
                lines.append(f"           actual={c['actual']!r}")
                lines.append(f"           expected={c['expected']!r}")
                if c.get("note"):
                    lines.append(f"           note={c['note']}")
            else:
                lines.append(f"    [INFO] {c.get('note')}")
    for note in payload.get("evaluation", {}).get("notes", []):
        # Avoid duplicating notes already shown inline
        if note and f"[INFO] {note}" not in "\n".join(lines):
            lines.append(f"  note: {note}")
    return "\n".join(lines)
