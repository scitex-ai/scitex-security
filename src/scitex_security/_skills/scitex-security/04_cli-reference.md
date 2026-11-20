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
| `scitex-security check <path>` | Run available code, dependency, credential and GitHub checks |
| `scitex-security github check <repo> --save` | Save report to `~/.scitex/security/runtime/` |
| `scitex-security github show-latest` | Print most recent saved report |
| `scitex-security list-python-apis` | List public Python API surface |
| `scitex-security skills list` | List bundled agent skill files |
| `scitex-security skills install` | Install skills into `~/.scitex/dev/skills/` |

| `scitex-security check-credentials <path> --json` | Read-only credential permissions and Git index checks; no secret values in reports |
| `scitex-security check-host --json` | Ubuntu/WSL patch, reboot and AppArmor observations; no upgrades/restarts |

### Universal flags

`--json` (emits structured JSON), `--help-recursive` (show all subcommand help).
