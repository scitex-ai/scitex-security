#!/usr/bin/env python3
# File: src/scitex_security/domains/__init__.py

"""Look-alike (typosquat / homograph) domain watch.

Generate look-alikes of a domain you own, find which are registered (DNS),
which carry mail exchangers (MX: a spoofed sender can send and receive),
which got certificates (Certificate Transparency via crt.sh) and when they
were registered (RDAP). Remember what was seen and alert only on what is
new.

Usage::

    from scitex_security.domains import generate_lookalike_domains, watch_domains

    generate_lookalike_domains("example.org")[:5]
    result = watch_domains(["example.org"], notify=False)
    for report in result["reports"]:
        print(report.domain, len(report.hits), [e.kind for e in report.events])
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional, Sequence

from ._alert import DEFAULT_MIN_INTERVAL_S, DEFAULT_PROFILE, compose_alert, send_alert
from ._candidates import (
    DEFAULT_PREFIXES,
    DEFAULT_SUFFIXES,
    DEFAULT_TLDS,
    Candidate,
    generate_lookalike_domains,
    registrable_domain,
    to_ascii,
)
from ._dns import DomainProbe, probe_domain, probe_domains
from ._watch import (
    Event,
    WatchReport,
    default_state_dir,
    peek_pending_events,
    pop_pending_events,
    watch_domain,
)
from ._web import Throttle, registration_date, search_certificates


def watch_domains(
    domains: Sequence[str],
    *,
    owned: Sequence[str] = (),
    state_dir: Optional[Path] = None,
    ct: bool = True,
    rdap: bool = True,
    notify: bool = False,
    profile: str = DEFAULT_PROFILE,
    min_interval_s: float = DEFAULT_MIN_INTERVAL_S,
    dry_run_notify: bool = False,
    rate_limit_dir: Optional[Path] = None,
    **probe_options,
) -> dict:
    """Watch several domains; optionally mail one notice for all new events.

    Every watched domain counts as owned by the others. Events stay pending
    in each domain's state file until a notice carrying them is accepted by
    the SMTP server, so a failed or rate-limited send loses nothing.

    Returns ``{"reports": [WatchReport], "pending": [event dicts],
    "notify": <scitex-notification result or None>}``.
    """
    domains = [to_ascii(d.strip().lower().rstrip(".")) or d for d in domains]
    all_owned = [*domains, *owned]
    throttle = Throttle(3.0)  # one crt.sh pace across all domains
    reports = [
        watch_domain(
            d,
            state_dir=state_dir,
            owned=all_owned,
            ct=ct,
            rdap=rdap,
            ct_throttle=throttle,
            **probe_options,
        )
        for d in domains
    ]
    pending = [e for d in domains for e in peek_pending_events(state_dir, d)]
    result = None
    if notify and pending:
        result = send_alert(
            pending,
            domains,
            profile=profile,
            min_interval_s=min_interval_s,
            dry_run=dry_run_notify,
            rate_limit_dir=rate_limit_dir,
        )
        if result.get("status") == "sent":
            for d in domains:
                pop_pending_events(state_dir, d)
    return {"reports": reports, "pending": pending, "notify": result}


__all__ = [
    "Candidate",
    "DomainProbe",
    "Event",
    "Throttle",
    "WatchReport",
    "DEFAULT_PREFIXES",
    "DEFAULT_SUFFIXES",
    "DEFAULT_TLDS",
    "compose_alert",
    "default_state_dir",
    "generate_lookalike_domains",
    "probe_domain",
    "probe_domains",
    "registrable_domain",
    "registration_date",
    "search_certificates",
    "send_alert",
    "to_ascii",
    "watch_domain",
    "watch_domains",
]

# EOF
