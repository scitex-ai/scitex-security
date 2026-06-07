# Changelog

All notable changes to `scitex-security` are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.2.0] — 2026-06-07 (DEPRECATED RELEASE)

### Deprecated

This release marks `scitex-security` as **DEPRECATED**. The package
has been absorbed into [`scitex-audit`](https://github.com/ywatanabe1989/scitex-audit)
per [ADR-0001](https://github.com/ywatanabe1989/scitex-dev/blob/develop/docs/adr/0001-absorb-scitex-security-into-scitex-audit.md)
(scitex-dev #139, Accepted 2026-06-07).

This release is a thin re-export shim provided for transition only.
The package will be yanked from PyPI in the W3 release wave (~1
release later) once `scitex-dev ecosystem reconcile-versions` confirms
zero downstream pins.

### Changed
- Hard runtime dep on `scitex-audit>=0.2.0` (where the implementation
  now lives). `click` is no longer a direct dep — pulled transitively
  by scitex-audit.
- `scitex_security/__init__.py` emits a `DeprecationWarning` on import.
- `scitex_security/github.py` is now a thin re-export of
  `scitex_audit.github` (all 10 public + helper symbols still resolve
  via the legacy path for one transition release).
- `scitex_security/cli.py` is replaced by a hard-error redirect
  (skill 11 §5): the `scitex-security` console script and
  `python -m scitex_security` print
  `error: scitex-security was absorbed into scitex-audit … Re-run with: scitex-audit github`
  and exit `2`. **No silent working alias** — per the ecosystem
  CLI-deprecation policy, soft warnings let stale scripts persist
  indefinitely; the hard error forces the fix in one iteration.
- `requires-python` bumped from 3.9 to 3.10 (matches scitex-audit's
  floor).
- `Development Status` classifier flipped to `7 - Inactive`.

### Removed
- `src/scitex_security/_paths.py` — superseded by `scitex_audit._paths`
  (path resolution + the legacy `~/.scitex/security/` →
  `~/.scitex/audit/github-alerts/` auto-symlink).
- `src/scitex_security/_skills.py` + `src/scitex_security/_skills/`
  — skills moved into `scitex-audit`'s bundle. The
  `[project.entry-points."scitex_dev.skills"]` entry-point is removed
  so the ecosystem skills CLI stops surfacing the deprecated package.
- `tests/scitex_security/test_github.py`, `tests/scitex_security/test_cli.py`,
  `tests/_helpers.py`, `tests/develop/test_audit.py` — covered the
  pre-absorption surface; replaced by a single
  `tests/scitex_security/test_shim.py` covering the legacy re-exports +
  DeprecationWarning + hard-error CLI.

### Migration

```diff
- pip install scitex-security
+ pip install "scitex-audit>=0.2.0"

- from scitex_security import check_github_alerts, GitHubSecurityError
+ from scitex_audit.github import check_github_alerts, GitHubSecurityError

- scitex-security check OWNER/REPO --save
+ scitex-audit github --repo OWNER/REPO --save
```

The `~/.scitex/security/` user data directory auto-symlinks to
`~/.scitex/audit/github-alerts/` on first import of `scitex_audit`
(skip-marker'd so it only fires once per user). No manual user step.

### Reference

- ADR-0001: <https://github.com/ywatanabe1989/scitex-dev/blob/develop/docs/adr/0001-absorb-scitex-security-into-scitex-audit.md>
- scitex-audit 0.2.0 release: <https://github.com/ywatanabe1989/scitex-audit/releases/tag/v0.2.0>

## [0.1.2]

- Initial CHANGELOG entry — see git log for prior history.
