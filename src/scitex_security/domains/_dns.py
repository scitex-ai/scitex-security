#!/usr/bin/env python3
# File: src/scitex_security/domains/_dns.py

"""DNS probing of candidate domains (A / AAAA / MX / NS).

The resolver is injected as a plain callable ``query(name, rtype) -> list``
so tests pass a real fake instead of patching the network. The default
uses dnspython against the host's configured resolver.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from typing import Callable, Iterable, Optional

#: Record types collected for a registered name, cheapest signal first.
RECORD_TYPES = ("A", "AAAA", "MX", "NS")


class DomainNotFound(LookupError):
    """NXDOMAIN: the name does not exist (not registered or not delegated)."""


class LookupFailed(RuntimeError):
    """The lookup itself failed (timeout, SERVFAIL); existence is unknown."""


QueryFn = Callable[[str, str], list]


@dataclass
class DomainProbe:
    """What DNS says about one name. ``registered`` is None when unknown."""

    name: str
    registered: Optional[bool]
    records: dict = field(default_factory=dict)
    error: Optional[str] = None

    @property
    def resolves(self) -> bool:
        return bool(self.records.get("A") or self.records.get("AAAA"))

    @property
    def has_mx(self) -> bool:
        return bool(self.records.get("MX"))

    def to_dict(self) -> dict:
        return asdict(self)


def dnspython_query(timeout: float = 5.0) -> QueryFn:
    """A :data:`QueryFn` backed by dnspython (imported here, not at module load)."""
    import dns.exception
    import dns.resolver

    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout

    def query(name: str, rtype: str) -> list:
        try:
            answer = resolver.resolve(name, rtype)
        except dns.resolver.NXDOMAIN as exc:
            raise DomainNotFound(name) from exc
        except dns.resolver.NoAnswer:
            return []
        except (dns.resolver.NoNameservers, dns.exception.Timeout) as exc:
            raise LookupFailed(f"{rtype} {name}: {type(exc).__name__}") from exc
        out = []
        for rdata in answer:
            if rtype == "MX":
                host = str(rdata.exchange).rstrip(".").lower()
                if host:  # "MX 0 ." is a null MX (RFC 7505): no mail at all
                    out.append(host)
            elif rtype == "NS":
                out.append(str(rdata.target).rstrip(".").lower())
            else:
                out.append(rdata.to_text())
        return sorted(set(out))

    return query


def _query_with_retry(query: QueryFn, name: str, rtype: str, retries: int) -> list:
    for attempt in range(retries + 1):
        try:
            return query(name, rtype)
        except LookupFailed:
            if attempt == retries:
                raise
    return []  # pragma: no cover -- loop always returns or raises


def probe_domain(
    name: str, query: Optional[QueryFn] = None, retries: int = 1
) -> DomainProbe:
    """Look up ``name`` (ASCII/punycode form).

    One A query settles most candidates: NXDOMAIN means unregistered and
    nothing more is asked. A name that exists gets AAAA, MX and NS too. A
    timed-out lookup is retried ``retries`` times before it counts as
    unknown.
    """
    query = query or dnspython_query()
    records: dict = {}
    errors = []
    for rtype in RECORD_TYPES:
        try:
            records[rtype] = _query_with_retry(query, name, rtype, retries)
        except DomainNotFound:
            if rtype == "A" or not any(records.values()):
                return DomainProbe(name, False)
            records[rtype] = []
        except LookupFailed as exc:
            errors.append(str(exc))
    if errors and not any(records.values()):
        return DomainProbe(name, None, records, "; ".join(errors))
    return DomainProbe(name, True, records, "; ".join(errors) or None)


def probe_domains(
    names: Iterable[str], query: Optional[QueryFn] = None, workers: int = 32
) -> dict:
    """Probe many names concurrently; returns ``{name: DomainProbe}``."""
    query = query or dnspython_query()
    names = list(dict.fromkeys(names))
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        probes = pool.map(lambda n: probe_domain(n, query), names)
        return {p.name: p for p in probes}


# EOF
