API
===

.. note::

   ``scitex-security`` is **DEPRECATED** as of v0.2.0. The
   GitHub-alerts implementation moved to ``scitex_audit.github`` per
   `ADR-0001 <https://github.com/ywatanabe1989/scitex-dev/blob/main/docs/adr/0001-absorb-scitex-security-into-scitex-audit.md>`_
   in scitex-dev #139. This package is a thin re-export shim for one
   transition release and will be yanked from PyPI in a future
   release. Use ``scitex-audit >= 0.2.0`` going forward.

Migration
---------

.. code-block:: diff

   - from scitex_security import check_github_alerts, GitHubSecurityError
   + from scitex_audit.github import check_github_alerts, GitHubSecurityError

   - scitex-security check OWNER/REPO --save
   + scitex-audit github check OWNER/REPO --save

The ``~/.scitex/security/`` data directory auto-symlinks to
``~/.scitex/audit/github-alerts/`` on first import of ``scitex_audit``
— no manual user step.

Public surface (re-exported from ``scitex_audit.github``)
---------------------------------------------------------

Imports below resolve to the canonical implementation in
``scitex_audit.github`` — see the
`scitex-audit docs <https://scitex-audit.readthedocs.io/>`_ for the
full signature reference.

* ``scitex_security.check_github_alerts``
* ``scitex_security.save_alerts_to_file``
* ``scitex_security.get_latest_alerts_file``
* ``scitex_security.format_alerts_report``
* ``scitex_security.GitHubSecurityError``

Deprecation CLI redirect
------------------------

The ``scitex-security`` console script is now a hard-error redirect
per the SciTeX CLI-deprecation skill (skill 11 §5):

.. code-block:: console

   $ scitex-security
   error: `scitex-security` was absorbed into scitex-audit
   (ADR-0001, scitex-dev #139).
   Re-run with: scitex-audit github
   …
   $ echo $?
   2
