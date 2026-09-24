# Contributing

## Setup

```bash
python -m pip install -e ".[dev]"
pytest
```

## Scope

Keep changes inside the v0 CLI surface: context JSON → claim prediction → trust JSON ALLOW/DENY, optional `hcl-dup` hygiene, exit codes `0`/`1`/`2`, docs.

Do **not** add without a maintainer decision:

- Checkov-class missing-`sub` lint as a primary surface
- Live AWS / STS scanning
- Multi-cloud / multi-IdP claim grammars
- Automatic workflow YAML trigger expand (later phase)
- Phone-home / SaaS credential collection

HCL duplicate detection must remain **secondary hygiene**; docs must prefer tflint.

## Tests

- Use `fixtures/` only (no network, no AWS)
- Assert exit codes `0` ALLOW / `1` DENY / `2` tool error
- Keep the PR → DENY on branch-pinned trust case (SO class) green

## License

By contributing you agree your contributions are licensed under Apache-2.0.
