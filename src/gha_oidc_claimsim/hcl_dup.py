"""Optional HCL duplicate Condition / StringEquals key hygiene.

Convenience only — prefer tflint ``terraform_map_duplicate_keys`` in CI.
Not unique IP (peers: tflint, Trail of Bits semgrep).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

KEY_RE = re.compile(
    r"""(?P<key>"[^"]+"|[A-Za-z_][A-Za-z0-9_]*)\s*="""
)

CONDITION_OPS = frozenset(
    {
        "StringEquals",
        "StringLike",
        "StringNotEquals",
        "StringNotLike",
        "ForAnyValue:StringEquals",
        "Condition",
    }
)


def find_duplicate_keys_in_objects(text: str) -> list[dict[str, Any]]:
    """Brace-scan object literals; report duplicate keys at each object scope."""
    findings: list[dict[str, Any]] = []
    stack: list[dict[str, Any]] = []
    line = 1
    i = 0
    n = len(text)

    while i < n:
        ch = text[i]
        if ch == "\n":
            line += 1
            i += 1
            continue
        if ch == "#" or text.startswith("//", i):
            while i < n and text[i] != "\n":
                i += 1
            continue
        if text.startswith("/*", i):
            end = text.find("*/", i + 2)
            if end == -1:
                break
            line += text[i:end].count("\n")
            i = end + 2
            continue
        if ch in "\"'":
            quote = ch
            i += 1
            while i < n:
                if text[i] == "\\":
                    i += 2
                    continue
                if text[i] == quote:
                    i += 1
                    break
                if text[i] == "\n":
                    line += 1
                i += 1
            continue

        if ch == "{":
            stack.append({"keys": {}, "start_line": line})
            i += 1
            continue
        if ch == "}":
            if stack:
                stack.pop()
            i += 1
            continue

        if stack:
            m = KEY_RE.match(text, i)
            if m:
                raw = m.group("key")
                key = raw[1:-1] if raw.startswith('"') else raw
                scope = stack[-1]
                if key in scope["keys"]:
                    findings.append(
                        {
                            "key": key,
                            "first_line": scope["keys"][key],
                            "duplicate_line": line,
                            "object_start_line": scope["start_line"],
                        }
                    )
                else:
                    scope["keys"][key] = line
                i = m.end()
                continue

        i += 1

    return findings


def condition_relevant_findings(
    findings: list[dict[str, Any]], text: str
) -> list[dict[str, Any]]:
    """Keep high-severity duplicate Condition / StringEquals operator keys."""
    relevant: list[dict[str, Any]] = []
    for f in findings:
        key = f["key"]
        if key in CONDITION_OPS:
            f = {**f, "severity": "high", "class": "duplicate-condition-operator"}
            relevant.append(f)
    return relevant


def scan_hcl_file(path: Path, *, high_only: bool = True) -> list[dict[str, Any]]:
    text = path.read_text(encoding="utf-8")
    findings = find_duplicate_keys_in_objects(text)
    if high_only:
        findings = condition_relevant_findings(findings, text)
    return findings


def format_hcl_report(path: Path, findings: list[dict[str, Any]]) -> str:
    lines = [f"=== HCL duplicate-key scan: {path} ==="]
    if not findings:
        lines.append("PASS: no duplicate Condition/StringEquals keys detected")
        lines.append(
            "Note: prefer tflint terraform_map_duplicate_keys in CI; "
            "this check is optional hygiene, not unique IP."
        )
        return "\n".join(lines)

    lines.append(f"FAIL: {len(findings)} duplicate key(s)")
    for f in findings:
        lines.append(
            f"  duplicate key {f['key']!r} at line {f['duplicate_line']} "
            f"(first at line {f['first_line']}, object starting line "
            f"{f['object_start_line']})"
        )
        lines.append(f"    class={f.get('class')} severity={f.get('severity')}")
        lines.append(
            "    effect: Terraform keeps LAST value — earlier StringEquals "
            "(e.g. sub restriction) silently dropped "
            "(Datadog GDS / HCSEC-2023-26)"
        )
    lines.append(
        "Note: prefer tflint terraform_map_duplicate_keys in CI; "
        "this check is optional hygiene, not unique IP."
    )
    return "\n".join(lines)
