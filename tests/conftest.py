"""Pytest fixtures and rootdir marker for this package.

Also performs module-import-time coverage wiring (parallel + subprocess
support). The tests at tests/examples/test_examples_smoke.py spawn child
Python interpreters via `subprocess.run([sys.executable, ...])`; without
this wiring their coverage is dropped silently.

`os.environ.setdefault` would be a no-op here because pytest-cov has
already set `COVERAGE_FILE` to a tmp dir by the time conftest is loaded.
Force-set, not setdefault.
"""

from __future__ import annotations

import os
import sys
import sysconfig
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_TESTS_ROOT = Path(__file__).resolve().parent

# Make ``tests/_helpers.py`` importable as ``from _helpers import ...``
# from any test module under ``tests/``. Tests sit in directories
# without ``__init__.py`` (rootdir mode), so pytest only adds each
# test's own directory to ``sys.path`` — we must add the shared
# ``tests/`` directory explicitly.
if str(_TESTS_ROOT) not in sys.path:
    sys.path.insert(0, str(_TESTS_ROOT))

# Pin coverage's data file at the repo root and point process_startup
# at our pyproject so child interpreters configure themselves correctly.
os.environ["COVERAGE_PROCESS_START"] = str(_PROJECT_ROOT / "pyproject.toml")
os.environ["COVERAGE_FILE"] = str(_PROJECT_ROOT / ".coverage")


def _ensure_subprocess_coverage_shim() -> None:
    """Drop an idempotent `.pth` file in site-packages that auto-starts
    coverage in every child Python interpreter via
    `coverage.process_startup()`.
    """
    purelib = Path(sysconfig.get_paths()["purelib"])
    pth = purelib / "_scitex_security_subprocess_coverage.pth"
    shim = (
        "import os, coverage\n"
        "if os.environ.get('COVERAGE_PROCESS_START'):\n"
        "    coverage.process_startup()\n"
    )
    try:
        if not pth.exists() or pth.read_text() != shim:
            pth.write_text(shim)
    except OSError:
        # site-packages may be read-only (e.g. system Python); silently
        # skip — local dev venvs are writable and that's where this matters.
        pass


_ensure_subprocess_coverage_shim()
