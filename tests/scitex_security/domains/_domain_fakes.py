"""Real fake collaborators for the domains tests (no unittest.mock, PA-306).

``FakeDNS`` answers ``query(name, rtype)`` from a zone dict; names absent
from the zone are NXDOMAIN. ``FakeWeb`` answers ``fetch(url, timeout)``
from URL-prefix rules and records every URL it was asked for.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from scitex_security.domains._dns import DomainNotFound, LookupFailed
from scitex_security.domains._web import FetchError


@dataclass
class FakeDNS:
    zone: dict = field(default_factory=dict)  # name -> {rtype: [values]}
    failing: set = field(default_factory=set)  # names whose lookups time out
    calls: list = field(default_factory=list)

    def __call__(self, name: str, rtype: str) -> list:
        self.calls.append((name, rtype))
        if name in self.failing:
            raise LookupFailed(f"{rtype} {name}: Timeout")
        if name not in self.zone:
            raise DomainNotFound(name)
        return list(self.zone[name].get(rtype, []))


@dataclass
class FakeWeb:
    routes: dict = field(default_factory=dict)  # url prefix -> payload | Exception
    urls: list = field(default_factory=list)

    def __call__(self, url: str, timeout: float) -> object:
        self.urls.append(url)
        for prefix, payload in self.routes.items():
            if url.startswith(prefix):
                if isinstance(payload, Exception):
                    raise payload
                return payload
        return None


def crt_row(cert_id: int, names: str, not_before: str = "2026-11-20T00:00:00"):
    return {
        "id": cert_id,
        "issuer_name": "C=US, O=Let's Encrypt, CN=R11",
        "common_name": names.splitlines()[0],
        "name_value": names,
        "not_before": not_before,
        "not_after": "2027-02-18T00:00:00",
        "entry_timestamp": not_before,
    }


def rdap_payload(created: str) -> dict:
    return {"events": [{"eventAction": "registration", "eventDate": created}]}


FETCH_ERROR = FetchError("https://crt.sh/: HTTP 503")

IANA = "https://data.iana.org/rdap/dns.json"
#: A bootstrap registry: .com/.ai at a fake registry, .jp absent (no RDAP).
BOOTSTRAP = {"services": [[["com", "ai"], ["https://rdap.test/v1/"]]]}
