#!/usr/bin/python3 -I
# -*- coding: utf-8 -*-
# File: src/scitex_security/_rotate/_entry.py

"""Bootstrap of the isolated rotation worker: ``python3 -I _entry.py <request-json>``.

``-I`` leaves only the standard library importable. This file makes
exactly one more directory importable -- the installed
``scitex_security`` package directory -- WITHOUT running
``scitex_security/__init__.py`` (whose dependencies are not stdlib and
must not load into the process holding the credential): it registers a
bare package module for ``scitex_security`` whose search path is that
directory, then imports :mod:`scitex_security._rotate._main`.
"""

import sys
import types
from pathlib import Path


def main() -> int:
    """Register the bare parent package, then run the worker."""
    pkg_dir = Path(__file__).resolve().parent.parent
    if "scitex_security" not in sys.modules:
        pkg = types.ModuleType("scitex_security")
        pkg.__path__ = [str(pkg_dir)]
        sys.modules["scitex_security"] = pkg
    from scitex_security._rotate._main import main as worker_main

    return worker_main(sys.argv[1:])


if __name__ == "__main__":
    sys.exit(main())


# EOF
