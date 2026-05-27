---
description: |
  [TOPIC] Quick Start
  [DETAILS] Smallest useful example demonstrating the primary use case in
  under 30 seconds.
tags: [scitex-security-quick-start]
---

# Quick Start

```python
from scitex_security import check_github_alerts, format_alerts_report

alerts = check_github_alerts()           # auto-detect current repo
print(format_alerts_report(alerts))      # formatted terminal output
```
