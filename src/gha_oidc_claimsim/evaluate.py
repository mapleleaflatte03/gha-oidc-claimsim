"""Simplified local IAM trust-policy evaluator for GitHub OIDC claims.

Models StringEquals / StringLike on
``token.actions.githubusercontent.com:sub`` and ``:aud`` only.
Not bit-identical to AWS IAM — fail-closed on unmodeled operators.
Empty Condition → DENY (AWS Jun-2025 spirit for new roles).
"""

from __future__ import annotations

import fnmatch
from typing import Any

SUB_KEY = "token.actions.githubusercontent.com:sub"
AUD_KEY = "token.actions.githubusercontent.com:aud"
MODELED_OPS = frozenset({"StringEquals", "StringLike"})
ASSUME_ACTIONS = frozenset(
    {
        "sts:AssumeRoleWithWebIdentity",
        "AssumeRoleWithWebIdentity",
    }
)

MODEL_CAVEAT = "simplified IAM Condition model"


def _as_list(v: Any) -> list[Any]:
    if v is None:
        return []
    if isinstance(v, list):
        return v
    return [v]


def _string_equals(actual: str, expected: Any) -> bool:
    return any(actual == e for e in _as_list(expected))


def _string_like(actual: str, pattern: Any) -> bool:
    """Approximate IAM StringLike with fnmatch (* and ?). Not bit-identical."""
    for p in _as_list(pattern):
        if fnmatch.fnmatchcase(actual, str(p)):
            return True
    return False


def _action_allows_web_identity(action: Any) -> bool:
    for a in _as_list(action):
        if a in ASSUME_ACTIONS:
            return True
        if isinstance(a, str) and a.endswith("AssumeRoleWithWebIdentity"):
            return True
    return False


def evaluate_trust(claims: dict[str, str], policy: dict[str, Any]) -> dict[str, Any]:
    """Evaluate predicted claims against an IAM role trust policy JSON.

    ALLOW if any modeled Allow + AssumeRoleWithWebIdentity statement fully
    matches on evaluated sub/aud conditions. Else DENY.
    """
    results: list[dict[str, Any]] = []
    overall = False
    notes: list[str] = []

    statements = policy.get("Statement")
    if statements is None:
        return {
            "allow": False,
            "statements": [],
            "notes": ["trust policy has no Statement"],
            "model_caveat": MODEL_CAVEAT,
        }

    for i, stmt in enumerate(_as_list(statements)):
        if not isinstance(stmt, dict):
            continue
        if stmt.get("Effect") != "Allow":
            continue
        if not _action_allows_web_identity(stmt.get("Action")):
            continue

        cond = stmt.get("Condition")
        checks: list[dict[str, Any]] = []
        ok = True

        if not cond:
            ok = False
            note = (
                "empty Condition — DENY (aligns with AWS Jun-2025 IdP controls "
                "spirit for new/updated roles)"
            )
            checks.append({"note": note})
            notes.append(note)
        elif not isinstance(cond, dict):
            ok = False
            note = "Condition is not an object — fail-closed"
            checks.append({"note": note})
            notes.append(note)
        else:
            for op, kv in cond.items():
                if not isinstance(kv, dict):
                    ok = False
                    note = f"Condition.{op} is not an object — fail-closed"
                    checks.append({"note": note, "op": op})
                    notes.append(note)
                    continue
                for key, expected in kv.items():
                    if key == SUB_KEY:
                        actual = claims["sub"]
                    elif key == AUD_KEY:
                        actual = claims["aud"]
                    else:
                        # Ignore unrelated condition keys in v0
                        continue

                    if op == "StringEquals":
                        matched = _string_equals(actual, expected)
                        check: dict[str, Any] = {
                            "key": key,
                            "op": op,
                            "actual": actual,
                            "expected": expected,
                            "matched": matched,
                        }
                    elif op == "StringLike":
                        matched = _string_like(actual, expected)
                        check = {
                            "key": key,
                            "op": op,
                            "actual": actual,
                            "expected": expected,
                            "matched": matched,
                            "note": "StringLike via fnmatch — approximate vs IAM",
                        }
                    else:
                        matched = False
                        note = f"operator {op} not modeled — fail-closed"
                        check = {
                            "key": key,
                            "op": op,
                            "actual": actual,
                            "expected": expected,
                            "matched": False,
                            "note": note,
                        }
                        notes.append(note)
                        ok = False
                        checks.append(check)
                        continue

                    checks.append(check)
                    if not matched:
                        ok = False

        results.append({"statement_index": i, "allow": ok, "checks": checks})
        if ok:
            overall = True

    return {
        "allow": overall,
        "statements": results,
        "notes": notes,
        "model_caveat": MODEL_CAVEAT,
    }
