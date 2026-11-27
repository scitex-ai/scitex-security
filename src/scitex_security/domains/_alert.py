#!/usr/bin/env python3
# File: src/scitex_security/domains/_alert.py

"""Mail new look-alike events as a scitex-notification ``notice``.

scitex-notification is an optional dependency (``scitex-security[notify]``),
imported only here and only when an alert is sent. It never falls back to
another mail path: a missing package or an unusable profile raises.
"""

from __future__ import annotations

import socket
from typing import Optional, Sequence

#: Default sender profile: From no-reply@ To the dev list, configured by
#: ``SCITEX_NOTIFICATION_PROFILE_OPS_*`` (see scitex-notification).
DEFAULT_PROFILE = "ops"
#: At most one alert mail per host per this many seconds. Events found in
#: between stay pending in the state files and go out with the next mail.
DEFAULT_MIN_INTERVAL_S = 6 * 3600.0
#: Event lines listed in one mail; the rest are counted.
MAX_LISTED_EVENTS = 30
AGENT_NAME = "scitex-security"

_RISK_ORDER = {"high": 0, "medium": 1, "low": 2}
_HINT = (
    "domain alerts need scitex-notification>=0.3.2: "
    "pip install 'scitex-security[notify]'"
)


def _notification():
    try:
        import scitex_notification
    except ImportError as exc:
        raise ImportError(_HINT) from exc
    return scitex_notification


def _event_line(event: dict) -> str:
    line = (
        f"[{event['risk']}] {event['kind']}: {event['name']}"
        f" (look-alike of {event['domain']}) {event['detail']}"
    )
    return " ".join(line.split())[:190]


def compose_alert(
    events: Sequence[dict], watched: Sequence[str], host: Optional[str] = None
) -> dict:
    """Notice data (for ``render_template("notice", ...)``) for ``events``."""
    host = host or socket.gethostname()
    ordered = sorted(
        events, key=lambda e: (_RISK_ORDER.get(e["risk"], 3), e["kind"], e["name"])
    )
    lines = [_event_line(e) for e in ordered[:MAX_LISTED_EVENTS]]
    if len(ordered) > MAX_LISTED_EVENTS:
        lines.append(
            f"+{len(ordered) - MAX_LISTED_EVENTS} more: "
            "scitex-security domains watch --json"
        )
    n_high = sum(1 for e in events if e["risk"] == "high")
    n_mx = sum(1 for e in events if e["kind"] == "new-mx" or "mx:" in e["detail"])
    title = f"{len(events)} new look-alike domain event(s) for {', '.join(watched)}"
    if n_high:
        title += f" ({n_high} high risk"
        title += f", {n_mx} with MX)" if n_mx else ")"
    return {
        "kind": "FYI",
        "title": title,
        "done": lines,
        "running": [
            f"daily look-alike watch of {', '.join(watched)} on {host}",
            "high = registered in the last 90 days, or brand-intact name with MX records",
        ],
        "meta": {"agent": AGENT_NAME, "host": host, "refs": "-"},
    }


def send_alert(
    events: Sequence[dict],
    watched: Sequence[str],
    *,
    profile: str = DEFAULT_PROFILE,
    min_interval_s: float = DEFAULT_MIN_INTERVAL_S,
    dry_run: bool = False,
    rate_limit_dir=None,
    host: Optional[str] = None,
) -> dict:
    """Render and send one notice for ``events`` via ``profile``.

    Returns scitex-notification's result (``status``: ``sent`` /
    ``suppressed`` / ``dry_run``). ``suppressed`` means the per-host
    interval has not elapsed; the caller keeps the events pending.
    """
    stxn = _notification()
    host = host or socket.gethostname()
    data = compose_alert(events, watched, host)
    subject, body = stxn.render_template("notice", data)
    html = stxn.render_message_html("notice", subject, body)
    return stxn.send_with_profile(
        profile,
        subject,
        body,
        template="notice",
        dedupe_key=f"scitex-security-domains:{host}",
        dedupe_window_s=min_interval_s,
        rate_limit_dir=rate_limit_dir,
        dry_run=dry_run,
        html_body=html,
    )


# EOF
