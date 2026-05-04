---
name: scitex-security
description: |
  [WHAT] Security helpers for SciTeX scripts — secret loading, redaction in logs, and safe path handling.
  [WHEN] Writing scripts that touch credentials, API keys, or user PII.
  [HOW] `from scitex_security import ...` or `scitex-security --help`.
primary_interface: python
interfaces:
  python: 2
  cli: 1
  mcp: 0
  skills: 2
  hook: 0
  http: 0
canonical-location: scitex-security/src/scitex_security/_skills/scitex-security/SKILL.md
tags: [scitex-security]
---

> **Interfaces:** Python ⭐⭐ · CLI ⭐ · MCP — · Skills ⭐⭐ · Hook — · HTTP —

# scitex-security

GitHub security-alert utilities. `check_github_alerts(repo=...)` returns the open Dependabot/CodeQL alerts as a structured list. Drop-in replacement for `gh api repos/{owner}/{repo}/dependabot/alerts` shell-outs in monitoring dashboards.

See README.md and the package's public `__init__.py` for the full
function list. This skill leaf exists so agents discover the package
exists and roughly what shape it has — refer to the source for
signatures.

## Sub-skills

### Core (01–09)
- [01_installation.md](01_installation.md) — install + import sanity check
- [02_quick-start.md](02_quick-start.md) — 30-second tour
- [03_python-api.md](03_python-api.md) — Python API surface
- [04_cli-reference.md](04_cli-reference.md) — CLI subcommands
