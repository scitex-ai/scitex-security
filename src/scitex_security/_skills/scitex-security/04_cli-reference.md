---
description: |
  [TOPIC] CLI Reference
  [DETAILS] scitex-security CLI subcommands — noun-verb structure with universal flags.
tags: [scitex-security-cli-reference]
---

# CLI Reference

```bash
scitex-security --help
```

| Command | Purpose |
|---|---|
| `scitex-security check <repo>` | Check Dependabot / CodeQL / secret-scanning alerts |
| `scitex-security check <repo> --save` | Save report to `~/.scitex/security/runtime/` |
| `scitex-security show-latest` | Print most recent saved report |
| `scitex-security list-python-apis` | List public Python API surface |
| `scitex-security skills list` | List bundled agent skill files |
| `scitex-security skills install` | Install skills into `~/.scitex/dev/skills/` |

### Universal flags

`--json` (emits structured JSON), `--help-recursive` (show all subcommand help).
