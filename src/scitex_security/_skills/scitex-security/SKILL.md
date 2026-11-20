---
name: scitex-security
description: |
  [WHAT] Code, dependency, credential and Ubuntu host checks, plus GitHub security alerts.
  [WHEN] Auditing repository or host security hygiene from a script or automation.
  [HOW] `from scitex_security import check_github_alerts` or `scitex-security --help`.
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

The canonical security package; scitex-audit is archived. `audit(path)` orchestrates repository checks. `audit_credentials(path, secret_paths=...)` inspects sensitive permissions and actual Git index content without recording values. `audit_host()` observes Ubuntu/WSL patch posture without installing updates or restarting services. `check_github_alerts(repo=...)` returns GitHub alerts.

Use the read-only checks to prepare findings and maintenance work. They do not establish that a host is uncompromised or fully patched. Preserve unknown/skipped coverage, keep fleet reports private, and never include credential contents in notifications or issue reports.

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

### Configuration (20–29)
- [20_env-vars.md](20_env-vars.md) — environment variables
