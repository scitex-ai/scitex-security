---
description: |
  [TOPIC] Python API
  [DETAILS] Public Python API of scitex-security — exported functions, signatures,
  return types, and minimal usage examples per function.
tags: [scitex-security-python-api]
---

# Python API

## check_github_alerts(repo=None, *, auth_check=..., secrets_fn=..., dependabot_fn=..., code_scanning_fn=...) -> dict

Check Dependabot, secret-scanning, and code-scanning alerts for a repo.

```python
from scitex_security import check_github_alerts

alerts = check_github_alerts("owner/repo")
# {'secrets': [...], 'dependabot': [...], 'code_scanning': [...]}

# Auto-detect current repo:
alerts = check_github_alerts()
```

## save_alerts_to_file(alerts, output_dir=None, create_symlink=True) -> Path

Save a formatted alert report to a timestamped file.

```python
from scitex_security import save_alerts_to_file

path = save_alerts_to_file(alerts)
# Default: ~/.scitex/security/runtime/security-<timestamp>.txt
```

## get_latest_alerts_file(security_dir=None) -> Path | None

Return the path to the most recent saved report, or `None`.

```python
from scitex_security import get_latest_alerts_file

latest = get_latest_alerts_file()
if latest:
    print(latest.read_text())
```

## format_alerts_report(alerts) -> str

Format a structured alerts dict into a human-readable string.

```python
from scitex_security import format_alerts_report

report = format_alerts_report(alerts)
print(report)
```

## GitHubSecurityError

Raised when the `gh` CLI is unavailable or returns an error.
