"""Quickstart for scitex_security.

Demonstrates formatting a GitHub security alerts report.

Note: live `check_github_alerts` requires `gh` CLI auth and a real repo.
This example shows the offline-safe `format_alerts_report` API on a
synthetic alerts dict shaped exactly like the live response.
"""

import scitex_security as ssec


def main() -> int:
    # Field names match what `check_github_alerts` returns from `gh api`.
    fake_alerts = {
        "secrets": [
            {
                "state": "open",
                "secretType": "github_personal_access_token",
                "path": "config/.env",
                "line": 12,
                "createdAt": "2026-04-01T12:00:00Z",
                "url": "https://github.com/example/repo/security/secret-scanning/1",
            }
        ],
        "dependabot": [
            {
                "state": "open",
                "severity": "high",
                "summary": "Prototype pollution in lodash",
                "package": "lodash",
                "cve": "CVE-2020-8203",
                "url": "https://github.com/example/repo/security/dependabot/2",
            }
        ],
        "code_scanning": [],
    }

    report = ssec.format_alerts_report(fake_alerts)
    print(report)

    # Sanity check the public API surface we just exercised
    assert "secrets" in report.lower() or "secret" in report.lower()
    print(
        "\nPublic API:",
        sorted(x for x in dir(ssec) if not x.startswith("_"))[:6],
        "...",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
