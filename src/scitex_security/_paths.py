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
