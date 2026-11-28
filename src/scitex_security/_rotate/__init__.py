#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File: src/scitex_security/_rotate/__init__.py

"""Operator-run credential rotation for signed, encrypted shell payloads.

The rotation itself runs under ``/usr/bin/python3 -I`` (no user site, no
``PYTHON*`` environment, no cwd on ``sys.path``) so that nothing outside
this directory can be imported into the process that holds the new
credential and the decrypted payload. Every module the worker imports
(:mod:`._entry`, :mod:`._main` and what it imports, and this
``__init__``) uses the standard library only. :mod:`._cli` (the click
command) and :mod:`._launch` belong to the launcher side: they resolve the
config chain, start :mod:`._entry` under that interpreter and render its
events, and the worker never imports them.

Flow (``rotate-credential PAYLOAD VARS [--dry-run]``):

1. read the new value from one hidden ``/dev/tty`` prompt (never argv,
   environment, file or log); check its shape and, for GitHub tokens,
   liveness;
2. verified-decrypt the current payload, replace exactly the named
   assignments, prove in clean bash that only those variables changed,
   re-encrypt to the same recipients and round-trip it;
3. build the candidate manifest = installed manifest + exactly one entry;
4. after a typed ``install`` confirmation, sign with the controller-only
   issuer key, install fleet-wide (hosts without the trust directory are
   skipped with a reason), and open a dotfiles PR (never merged).

``--dry-run`` stops before signing, in a temporary directory it removes.
"""

# EOF
