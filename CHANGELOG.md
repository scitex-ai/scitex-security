# Changelog

All notable changes to `scitex-security` are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- **Secret redaction** (`scitex-security redact SOURCE`, `redact_text`,
  `build_redactor`). Detection is gitleaks (`gitleaks stdin`, maintained
  upstream rules; packaged `_redact/gitleaks.toml` with `[extend]
  useDefault = true`, overridable with `--config` or `redact.gitleaks_config`
  in the config chain) together with the exact live values of
  credential-named env vars, whatever their format. Text mode filters a file
  or `-` (stdin) to stdout. `--hook claude-post-tool-use` implements the Claude Code
  PostToolUse contract (`hookSpecificOutput.updatedToolOutput` for Bash
  stdout/stderr). Per-tool adapters let Read/Grep/WebFetch be added later.
  When gitleaks is missing or fails, exact-value redaction still runs and a
  warning is emitted; it never fails open silently. This responds to the
  2026-11-28 incident in which a fine-grained GitHub PAT got past a
  hand-written pattern list.
- **Operator-run credential rotation** (`scitex-security rotate-credential
  PAYLOAD VARS [--dry-run]`), ported from the unversioned controller tool.
  The value comes from a hidden `/dev/tty` prompt only. The work runs in an
  isolated `python -I` worker that reports to the launcher through JSON
  events carrying names, statuses and hashes. The worker proves that only
  the named variables changed in a clean bash, re-encrypts to the same
  recipients, builds the installed manifest plus exactly one entry, and asks
  for a typed `install` confirmation before signing. It then installs on
  every configured host, skipping hosts without the trust dir and reporting
  why, and opens a dotfiles PR. Hosts, controller, issuer fingerprint, paths
  and GitHub-token routing are config (`rotate_credential:`); no fleet facts
  are hardcoded.
- SciTeX config chain loader (`--config` → `$SCITEX_SECURITY_CONFIG` →
  `<project>/.scitex/security/config.yaml` → `~/.scitex/security/config.yaml`);
  new dependency `pyyaml`.

## [0.3.1] — 2026-11-27

First published release of the 0.3 line; contents are those of 0.3.0 below.

### Fixed

- Release pipeline: the tag workflow's `.github/ci` scripts were stale and
  demanded an apptainer shim path the current org runners do not have, so
  every test leg of the v0.3.0 tag failed before building. **0.3.0 was never
  published to PyPI.** Ported the host-agnostic SIF release scripts and
  workflow scitex-notification releases with (apptainer from the shim or
  PATH, job-owned scratch, image verified by the new repo variable
  `SCITEX_CI_SIF_SHA256`).

## [0.3.0] — 2026-11-27

### Added

- **Look-alike domain watch** (`scitex_security.domains`,
  `scitex-security domains {list-candidates,watch}`). Generates typo
  (omission, repetition, transposition, adjacent-key), homoglyph / IDN
  (Cyrillic, Greek, accented Latin, ASCII `rn`/`m` etc., punycode forms),
  TLD-swap, hyphenation and prefix/suffix look-alikes of a domain; probes
  A/AAAA/MX/NS (dnspython), searches Certificate Transparency (crt.sh,
  cached and spaced) and RDAP registration dates (IANA bootstrap, direct to
  each registry). State per domain under `$SCITEX_DIR/security/domains/`;
  only new registrations, new MX records and new certificates raise events,
  the first run is a baseline. `--notify` mails one scitex-notification
  `notice` per run via the `ops` profile, at most once per 6 h per host;
  undelivered events stay pending. Daily systemd user units in
  `examples/systemd/`.
- Optional extra `notify` (`scitex-notification>=0.3.2`).

### Changed

- New runtime dependency `dnspython>=2.4` (pure Python) for MX/NS lookups.
- Package diagnostics use `scitex-logging` instead of stdlib `logging`
  (PS-220); new runtime dependency `scitex-logging>=0.2.1`.
- CI: `ci.yml` is now the canonical org-reusable caller, so it publishes the
  `pytest-matrix / ...` contexts branch protection already requires (the old
  local jobs published unprefixed names, so required checks never arrived).
  `cla.yml` calls the org CLA workflow; the local copy stored signatures on a
  `cla-signatures` branch that does not exist, failing every PR.
- `.scitex/security/runtime/` is ignored, not tracked (PS-234).

### Fixed

- `pyproject.toml` carried a stray `dependencies` key under
  `[tool.scitex-linter]`, which made the scitex-dev linter crash on load.

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
