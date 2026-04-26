# scitex-security

GitHub security-alert utilities (Dependabot, secret scanning, code scanning) extracted from the [SciTeX](https://github.com/ywatanabe1989/scitex-python) ecosystem as a standalone, zero-dep package.

## Install

```bash
pip install scitex-security
```

## Usage

### Library

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

### CLI

```bash
scitex-security check ywatanabe1989/myrepo
scitex-security latest --output .scitex/security
```

## Status

Standalone fork of `scitex.security`. Pure stdlib + `gh` CLI subprocess —
zero scitex.* runtime deps. Umbrella `scitex.security` import path is
preserved via a `sys.modules`-alias bridge.

## License

AGPL-3.0-only (see [LICENSE](./LICENSE)).
