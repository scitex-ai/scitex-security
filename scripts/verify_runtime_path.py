#!/usr/bin/env python3
"""Verify that scitex-security paths resolve under <pkg>/runtime/.

Run from the repo root or with --root <path>. Exits 0 if every
regenerable-data path contains '/runtime/', 1 otherwise.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path


def _find_repo_root(start: Path) -> Path:
    for parent in [start] + list(start.parents):
        git_path = parent / ".git"
        if git_path.is_dir() or git_path.is_file():
            return parent
    msg = f"no .git found from {start}"
    raise RuntimeError(msg)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=os.getcwd())
    opts = parser.parse_args()

    # Insert the source tree so we can import the package
    root = _find_repo_root(Path(opts.root).resolve())
    src = root / "src"
    sys.path.insert(0, str(src))

    from scitex_security._paths import PKG_SHORT, get_default_alerts_dir

    failures: list[str] = []

    # 1. Default alerts dir must resolve under <pkg>/runtime/
    d = get_default_alerts_dir()
    if PKG_SHORT + "/runtime" not in str(d):
        failures.append(
            f"get_default_alerts_dir() -> {d}  (expected .../{PKG_SHORT}/runtime/...)"
        )

    # 5. PKG_SHORT must be correct
    if PKG_SHORT != "security":
        failures.append(f"PKG_SHORT={PKG_SHORT!r}  (expected 'security')")

    if failures:
        for f in failures:
            print(f"FAIL: {f}", file=sys.stderr)
        return 1

    print(f"OK: get_default_alerts_dir() = {d}  (contains /runtime/)")
    print(f"OK: PKG_SHORT = {PKG_SHORT!r}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
