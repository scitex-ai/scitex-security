# Changelog

All notable changes to `scitex-security` are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.2.0] — 2026-06-07 (UNIFIED SURVIVOR per ADR-0002)

This release is the **unified** scitex-security: the GitHub-alerts
checker from 0.1.x **plus** the multi-tool security-audit orchestrator
(bandit + shellcheck + pip-audit) absorbed from `scitex-audit` 0.2.0
per [ADR-0002](https://github.com/ywatanabe1989/scitex-dev/blob/develop/docs/adr/0002-reverse-absorption-direction-scitex-audit-into-scitex-security.md)
(scitex-dev #142, Accepted 2026-06-07).

### Context — direction reversal

ADR-0001 originally absorbed scitex-security INTO scitex-audit
(W1-forward). The W1 wave shipped through scitex-audit 0.2.0 (live on
PyPI) plus dependent merges in scitex-dev (#141) and scitex-python
(#322). Mid-wave, the operator reversed the absorption direction:
"security" is the better unified-package name; "audit" reads as the
narrower / more ambiguous label. ADR-0002 documents the reversal and
its recovery plan. scitex-audit 0.2.0 stays on PyPI as historical
(no yank — yanks break installed callers). The next `scitex-audit`
release (0.3.0) becomes a thin deprecated shim of this package.

### Added

- **Multi-tool security-audit orchestrator** — `scitex_security.audit(
  path, checks, output_file) → dict`. Discovers and runs bandit
  (Python), shellcheck (shell), pip-audit (deps), and the GitHub
  alerts checker. Skips checks whose backing tool isn't installed.
  Verbatim port of `scitex_audit._runner.audit` from 0.2.0.
- New internal modules `_bandit`, `_shellcheck`, `_pip_audit`,
  `_format`, `_runner`, `_github_runner` — ported from scitex-audit
  0.2.0 (renamed `_github` → `_github_runner` to avoid colliding with
  the public `github.py`).
- CLI restructured per the noun-verb catalog (lead-approved 2026-06-07):
  - `scitex-security check [PATH]` — intransitive full multi-tool sweep.
  - `scitex-security github check [REPO]` — GH-alerts subset (was the
    top-level `scitex-security check REPO` in 0.1.x).
  - `scitex-security github show-latest` — print the most recent saved
    GH-alerts report (was the top-level `scitex-security show-latest`).
- Auto **reverse-migration** of `~/.scitex/audit/github-alerts/` →
  `~/.scitex/security/runtime/` on first import after upgrade. Users
  who ran scitex-audit 0.2.0 get their data automatically moved back
  to the canonical scitex-security location. Symlink-preferred,
  move-fallback, marker-gated, never raises.

### Changed

- `pyproject.toml`:
  - `version` 0.1.4 → 0.2.0.
  - Description updated to reflect the unified scope.
  - `requires-python` bumped 3.9 → 3.10 (matches the scitex-audit
    0.2.0 baseline we absorbed).

### Migration

- **From scitex-audit 0.2.0 callers:** switch
  `from scitex_audit import audit` →
  `from scitex_security import audit`. Same signature, same return
  shape. `from scitex_audit.github import …` → `from scitex_security
  import …` (or `scitex_security.github.…`).
- **CLI:** `scitex-audit check` → `scitex-security check` (same
  intransitive multi-tool semantics). `scitex-audit github check`
  → `scitex-security github check` (same noun-verb shape).
- **Data dir:** `~/.scitex/audit/github-alerts/` auto-symlinks to
  `~/.scitex/security/runtime/` on first import — no manual step.

### Reference

- ADR-0002 (this absorption direction): `scitex-dev` docs/adr/0002-…md
  (PR ywatanabe1989/scitex-dev#142).
- ADR-0001 (the now-superseded forward direction): same dir, 0001-…md.
- scitex-audit 0.2.0 (the historical artifact this release supersedes):
  https://pypi.org/project/scitex-audit/0.2.0/

## [0.1.2]

- Initial CHANGELOG entry — see git log for prior history.
