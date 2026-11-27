"""Tests for the alert notice: layout validity, ordering, rate limit.

Renders through the real scitex-notification ``notice`` template, and
sends only as ``dry_run`` (validation + rate-limit peek, no SMTP).
"""

import os

import pytest

from scitex_security.domains._alert import compose_alert, send_alert

stxn = pytest.importorskip("scitex_notification")

EVENTS = [
    {"kind": "new-registration", "domain": "example.ai", "name": "getexample.ai",
     "detail": "ns: ns.test", "risk": "low"},
    {"kind": "new-mx", "domain": "example.ai", "name": "example-ai.com",
     "detail": "mx: mx.evil.test", "risk": "high"},
]  # fmt: skip

PROFILE_ENV = {
    "SCITEX_NOTIFICATION_PROFILE_DOMAINSTEST_FROM": "no-reply@example.org",
    "SCITEX_NOTIFICATION_PROFILE_DOMAINSTEST_TO": "dev@example.org",
    "SCITEX_NOTIFICATION_PROFILE_DOMAINSTEST_SMTP_HOST": "smtp.example.org",
}


def test_alert_renders_as_a_valid_notice():
    # Arrange
    data = compose_alert(EVENTS, ["example.ai"], host="h1")
    # Act
    subject, _body = stxn.render_template("notice", data)
    # Assert
    assert subject.startswith("[SciTeX][scitex-security] FYI: 2 new look-alike")


def test_alert_lists_high_risk_first():
    # Arrange
    events = EVENTS
    # Act
    data = compose_alert(events, ["example.ai"], host="h1")
    # Assert
    assert data["done"][0].startswith("[high] new-mx: example-ai.com")


def test_alert_caps_listed_events():
    # Arrange
    events = [dict(EVENTS[0], name=f"n{i}.ai") for i in range(45)]
    # Act
    data = compose_alert(events, ["example.ai"], host="h1")
    # Assert
    assert data["done"][-1].startswith("+15 more")


def test_dry_run_send_validates_and_would_send(tmp_path):
    # Arrange
    os.environ.update(PROFILE_ENV)
    try:
        # Act
        result = send_alert(
            EVENTS, ["example.ai"], profile="domainstest", dry_run=True,
            rate_limit_dir=tmp_path, host="h1",
        )  # fmt: skip
    finally:
        for key in PROFILE_ENV:
            os.environ.pop(key, None)
    # Assert
    assert (result["status"], result["would_send"]) == ("dry_run", True)
