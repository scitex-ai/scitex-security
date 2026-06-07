"""Path resolution for scitex-security local state.

Follows the SciTeX local-state-directories convention
(``01_ecosystem/06_local-state-directories.md``):

* Regenerable data (alert reports, symlinks) goes under
  ``<pkg-short>/runtime/`` — never outside the package namespace.
* Resolves via ``SCITEX_SECURITY_DIR`` env var, project scope, or user
  scope (in that precedence order).
* ``SCITEX_DIR`` relocates the user-scope root atomically.
* Standalone resolver — no ``scitex_dev`` import, no ``PathManager``
  dependency.
"""

from __future__ import annotations

import logging as _logging
import os
import shutil
import warnings
from pathlib import Path

#: Package short name (``scitex-security`` → ``security``).
PKG_SHORT = "security"

#: Legacy location (pre-v0.2) — CWD-relative.
_LEGACY_ALERTS_DIR_REL = Path("logs") / "security"

#: Marker file inside the primary dir signalling that legacy migration
#: has already run for this workspace.
_MIGRATION_MARKER = ".migrated_from_legacy"

#: Subdir under the SciTeX root that scitex-audit 0.2.0 wrote into
#: (during the ADR-0001 forward direction we later reversed).
_LEGACY_AUDIT_ALERTS_SUBPATH = Path("audit") / "github-alerts"

#: Marker file recording the one-shot reverse migration of
#: ``~/.scitex/audit/github-alerts/`` → ``~/.scitex/security/runtime/``.
_LEGACY_AUDIT_REVERSE_MARKER = ".migrated_from_scitex_audit_user"

_logger = _logging.getLogger(__name__)


def _project_root() -> Path | None:
    """Walk up from ``cwd`` to find the repository root (``.git`` sentinel)."""
    cwd = Path.cwd().resolve()
    for parent in [cwd] + list(cwd.parents):
        if (parent / ".git").is_dir():
            return parent
    return None


def _resolve_user_scope() -> Path:
    """User-scope root, respecting ``$SCITEX_DIR``.

    Returns ``~/.scitex/security/runtime/`` (or ``$SCITEX_DIR/security/runtime/``
    when ``SCITEX_DIR`` is set).
    """
    scitex_dir = os.environ.get(
        "SCITEX_DIR",
        Path.home() / ".scitex",
    )
    return Path(scitex_dir).expanduser().resolve() / PKG_SHORT / "runtime"


def _resolve_project_scope() -> Path | None:
    """Project-scope root, if inside a git repo.

    Returns ``<project>/.scitex/security/runtime/`` or ``None``.
    """
    root = _project_root()
    if root is None:
        return None
    return root / ".scitex" / PKG_SHORT / "runtime"


def _get_primary_alerts_dir() -> Path:
    """Resolve the primary alerts directory with full precedence chain.

    Precedence (highest first):

    1. ``$SCITEX_SECURITY_DIR`` env var
    2. Project scope  (``<project>/.scitex/security/runtime/``)
    3. User scope     (``~/.scitex/security/runtime/`` or
                      ``$SCITEX_DIR/security/runtime/``)
    """
    env = os.environ.get("SCITEX_SECURITY_DIR")
    if env:
        return Path(env).expanduser().resolve()

    project = _resolve_project_scope()
    if project is not None:
        return project

    return _resolve_user_scope()


# ---------------------------------------------------------------------------
# Legacy migration (back-compat per §8 of local-state-directories)
# ---------------------------------------------------------------------------


def _legacy_alerts_dir_exists() -> bool:
    """Check if the old CWD-relative ``./logs/security`` exists."""
    return _LEGACY_ALERTS_DIR_REL.is_dir()


def _migrate_from_legacy(primary: Path) -> None:
    """One-time migration: move ``./logs/security/*`` → *primary*.

    Only runs if *primary* was not previously migrated (marker file
    guard).  Emits a ``DeprecationWarning`` on first occurrence.
    """
    if not _legacy_alerts_dir_exists():
        return

    marker = primary / _MIGRATION_MARKER
    if marker.exists():
        return

    legacy = _LEGACY_ALERTS_DIR_REL.resolve()
    warnings.warn(
        f"DEPRECATED: {legacy} is deprecated. "
        f"Alert files are now written to {primary}. "
        f"Set $SCITEX_SECURITY_DIR to override.",
        DeprecationWarning,
        stacklevel=3,
    )

    primary.mkdir(parents=True, exist_ok=True)
    for f in legacy.glob("security-*.txt"):
        shutil.move(str(f), str(primary / f.name))

    # Clean up the old symlink if it exists
    old_link = legacy / "security-latest.txt"
    if old_link.is_symlink() or old_link.exists():
        old_link.unlink()

    marker.touch()


def _check_legacy_fallback_read(target_dir: Path | None) -> Path | None:
    """If *target_dir* is the default and the legacy dir exists, return it.

    Keeps the old path readable for one minor version per §8.  Guards
    against infinite loops because ``get_latest_alerts_file`` is the
    caller in that path.
    """
    if target_dir is not None:
        return target_dir
    if _legacy_alerts_dir_exists():
        return _LEGACY_ALERTS_DIR_REL.resolve()
    return None


def get_default_alerts_dir() -> Path:
    """Return the default alerts directory, creating it if needed.

    Runs one-time migration from ``./logs/security`` when the legacy
    directory is detected.
    """
    primary = _get_primary_alerts_dir()
    _migrate_from_legacy(primary)
    primary.mkdir(parents=True, exist_ok=True)
    return primary


# ---------------------------------------------------------------------------
# Reverse migration: ~/.scitex/audit/github-alerts/ (from scitex-audit 0.2.0)
# back to ~/.scitex/security/runtime/, per ADR-0002 (scitex-dev #142).
#
# scitex-audit 0.2.0 was the ADR-0001-forward absorbing release. It
# auto-symlinked ~/.scitex/security/ → ~/.scitex/audit/github-alerts/.
# The reversal (ADR-0002) flips ownership back to scitex-security; users
# who imported scitex-audit 0.2.0 have their data sitting under
# ~/.scitex/audit/github-alerts/. This helper detects that layout on
# first import after upgrade and reverse-symlinks it back to the
# canonical ~/.scitex/security/runtime/ tree. Marker-gated so it only
# fires once per user.
# ---------------------------------------------------------------------------


def _scitex_dir() -> Path:
    """User-scope SciTeX root (``$SCITEX_DIR`` or ``~/.scitex``)."""
    raw = os.environ.get("SCITEX_DIR", Path.home() / ".scitex")
    return Path(raw).expanduser().resolve()


def _legacy_audit_alerts_dir() -> Path:
    """Path that scitex-audit 0.2.0 wrote to under the SciTeX root."""
    return _scitex_dir() / _LEGACY_AUDIT_ALERTS_SUBPATH


def _migrate_legacy_audit_dir() -> None:
    """One-shot reverse migration of legacy ``~/.scitex/audit/github-alerts/``.

    Triggered automatically on first import of ``scitex_security`` after
    upgrade (called from ``scitex_security/__init__.py``). Guarded by a
    marker file so it only fires once per user. Per ADR-0002 §"Locked
    decisions": NO manual user step. Prefers ``os.symlink`` so users
    keep one storage location; falls back to ``shutil.move`` when
    symlinks aren't available on the platform.

    No-ops if the legacy audit dir doesn't exist, or if the
    canonical scitex-security dir already exists with content, or if
    the marker file says we already migrated.
    """
    legacy = _legacy_audit_alerts_dir()
    if not legacy.exists():
        return

    security_root = _scitex_dir() / PKG_SHORT
    marker = security_root / _LEGACY_AUDIT_REVERSE_MARKER
    if marker.exists():
        return

    target = security_root / "runtime"
    if target.exists() and any(target.iterdir()):
        # The canonical location already has data — the user is mixing
        # both clients or has manually managed the dirs. Record the
        # marker so we don't keep re-checking, but don't overwrite.
        security_root.mkdir(parents=True, exist_ok=True)
        marker.touch()
        return

    security_root.mkdir(parents=True, exist_ok=True)
    if target.exists():
        # empty dir — remove so the symlink can point at the legacy.
        target.rmdir()

    moved = False
    try:
        os.symlink(legacy, target)
        _logger.info(
            "scitex-security: reverse-linked legacy %s → %s "
            "(per ADR-0002, scitex-dev #142).",
            legacy,
            target,
        )
        moved = True
    except OSError:
        try:
            shutil.move(str(legacy), str(target))
            _logger.info(
                "scitex-security: reverse-moved legacy %s → %s "
                "(per ADR-0002, scitex-dev #142).",
                legacy,
                target,
            )
            moved = True
        except OSError as exc:
            _logger.warning(
                "scitex-security: could not reverse-migrate legacy %s → %s: %s. "
                "Continuing with the canonical location empty; the legacy "
                "data is still readable at %s.",
                legacy,
                target,
                exc,
                legacy,
            )

    if moved:
        marker.touch()
