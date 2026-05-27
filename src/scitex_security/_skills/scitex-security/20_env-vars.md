---
description: |
  [TOPIC] Environment variables
  [DETAILS] Environment variables that control scitex-security behaviour.
tags: [scitex-security-env-vars]
---

# Environment Variables

| Variable | Purpose | Default |
|---|---|---|
| `SCITEX_SECURITY_CONFIG` | Path to YAML config (overrides `~/.scitex/security/config.yaml`). | unset |
| `SCITEX_SECURITY_DIR` | Override the alerts output directory. | unset (uses `<project>/.scitex/security/runtime/` or `~/.scitex/security/runtime/`) |
| `SCITEX_DIR` | Relocate the entire user-scope tree. | `~/.scitex` |
| `GH_TOKEN` / `GITHUB_TOKEN` | Auth token for the `gh` CLI subprocess. | unset |

See `01_ecosystem/04_environment-variables.md` and `01_ecosystem/06_local-state-directories.md` for conventions.
