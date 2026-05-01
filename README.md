# scitex-security

<!-- scitex-badges:start -->
[![PyPI](https://img.shields.io/pypi/v/scitex-security.svg)](https://pypi.org/project/scitex-security/)
[![Python](https://img.shields.io/pypi/pyversions/scitex-security.svg)](https://pypi.org/project/scitex-security/)
[![Tests](https://github.com/ywatanabe1989/scitex-security/actions/workflows/test.yml/badge.svg)](https://github.com/ywatanabe1989/scitex-security/actions/workflows/test.yml)
[![Install Test](https://github.com/ywatanabe1989/scitex-security/actions/workflows/install-test.yml/badge.svg)](https://github.com/ywatanabe1989/scitex-security/actions/workflows/install-test.yml)
[![Coverage](https://codecov.io/gh/ywatanabe1989/scitex-security/graph/badge.svg)](https://codecov.io/gh/ywatanabe1989/scitex-security)
[![Docs](https://readthedocs.org/projects/scitex-security/badge/?version=latest)](https://scitex-security.readthedocs.io/en/latest/)
[![License: AGPL v3](https://img.shields.io/badge/license-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
<!-- scitex-badges:end -->

<p align="center">
  <a href="https://scitex.ai">
    <img src="docs/scitex-logo-blue-cropped.png" alt="SciTeX" width="400">
  </a>
</p>

<p align="center"><b>GitHub security-alert utilities — Dependabot, secret scanning, code scanning. Pure stdlib + `gh` subprocess, zero scitex.* runtime deps.</b></p>

<p align="center">
  <a href="https://scitex-security.readthedocs.io/">Full Documentation</a> · <code>pip install scitex-security</code>
</p>

---

## Installation

```bash
pip install scitex-security
```

## 2 Interfaces

<details open>
<summary><strong>Python API</strong></summary>

<br>

```python
from scitex_security import (
    check_github_alerts,
    save_alerts_to_file,
    format_alerts_report,
    GitHubSecurityError,
)

alerts = check_github_alerts(repo="ywatanabe1989/myrepo")
print(format_alerts_report(alerts))
save_alerts_to_file(alerts, output_dir=".scitex/security")
```

</details>

<details>
<summary><strong>CLI</strong></summary>

<br>

```bash
scitex-security check ywatanabe1989/myrepo
scitex-security latest --output .scitex/security
```

</details>

## Status

Standalone fork of `scitex.security`. Pure stdlib + `gh` CLI subprocess —
zero scitex.* runtime deps. Umbrella `scitex.security` import path is
preserved via a `sys.modules`-alias bridge.

## Part of SciTeX

`scitex-security` is part of [**SciTeX**](https://scitex.ai). Install via
the umbrella with `pip install scitex[security]` to use as
`scitex.security` (Python) or `scitex security ...` (CLI).

>Four Freedoms for Research
>
>0. The freedom to **run** your research anywhere — your machine, your terms.
>1. The freedom to **study** how every step works — from raw data to final manuscript.
>2. The freedom to **redistribute** your workflows, not just your papers.
>3. The freedom to **modify** any module and share improvements with the community.
>
>AGPL-3.0 — because we believe research infrastructure deserves the same freedoms as the software it runs on.

## License

AGPL-3.0-only (see [LICENSE](./LICENSE)).

---

<p align="center">
  <a href="https://scitex.ai" target="_blank"><img src="docs/scitex-icon-navy-inverted.png" alt="SciTeX" width="40"/></a>
</p>
