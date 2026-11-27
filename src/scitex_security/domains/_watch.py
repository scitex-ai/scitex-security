#!/usr/bin/env python3
# File: src/scitex_security/domains/_watch.py

"""Watch look-alikes of a domain: probe, remember, report only what is new.

One JSON state file per watched domain records every look-alike seen
registered, its DNS records, registration date and the CT certificates
seen. A run compares against that state and emits events only for:

* ``new-registration`` -- a look-alike that was not registered before;
* ``new-mx``           -- a look-alike gained mail exchangers (it can now
                          send/receive mail as a spoofed sender);
* ``new-cert``         -- a new unexpired certificate for a look-alike name.

The first run for a domain is a *baseline*: everything is recorded and
reported, but no event is raised (nothing is "new" yet).
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable, Optional, Sequence

from ._candidates import (
    DEFAULT_PREFIXES,
    DEFAULT_SUFFIXES,
    DEFAULT_TLDS,
    Candidate,
    generate_lookalike_domains,
    registrable_domain,
    split_domain,
    to_ascii,
)
from ._dns import DomainProbe, QueryFn, dnspython_query, probe_domains
from ._web import FetchError, FetchFn, Throttle, registration_dates, search_certificates

STATE_VERSION = 1
#: A registration or certificate younger than this is flagged high risk.
RECENT_DAYS = 90


def default_state_dir() -> Path:
    """``$SCITEX_SECURITY_DIR/domains`` or ``$SCITEX_DIR/security/domains``.

    Deliberately not project-scoped: a watcher's memory must not depend on
    the directory it happens to be started from.
    """
    env = os.environ.get("SCITEX_SECURITY_DIR")
    if env:
        return Path(env).expanduser() / "domains"
    root = Path(os.environ.get("SCITEX_DIR", Path.home() / ".scitex")).expanduser()
    return root / "security" / "domains"


@dataclass
class Event:
    kind: str  # new-registration | new-mx | new-cert
    domain: str  # the watched domain
    name: str  # the look-alike (display form)
    detail: str
    risk: str

    @property
    def key(self) -> str:
        return f"{self.kind}|{self.domain}|{self.name}|{self.detail}"


@dataclass
class WatchReport:
    domain: str
    baseline: bool
    candidates: int
    hits: list = field(default_factory=list)  # rows, see _hit_row
    events: list = field(default_factory=list)  # Event
    errors: list = field(default_factory=list)
    state_path: str = ""

    def to_dict(self) -> dict:
        out = asdict(self)
        out["events"] = [asdict(e) for e in self.events]
        return out


def _today(now: Optional[datetime]) -> date:
    return (now or datetime.now(timezone.utc)).astimezone(timezone.utc).date()


def _is_recent(day: Optional[str], today: date) -> bool:
    try:
        return (today - date.fromisoformat(str(day)[:10])) <= timedelta(RECENT_DAYS)
    except ValueError:
        return False


#: Generators whose output keeps the whole brand intact (``example-app.com``,
#: ``example.net``, ``ехample.ai``). A single-letter typo of a short brand is
#: often an unrelated real word (an existing company), so typos weigh less.
BRAND_KINDS = frozenset({"homoglyph", "tld-swap", "affix", "hyphenation"})


def is_brand_intact(entry: dict, ascii_name: str, label: str) -> bool:
    """Generated brand-keeping kinds, or a CT-found name whose label IS the
    brand (``example.de``) or the brand plus a hyphenated word
    (``example-pay.com``). A longer word that merely starts with the brand
    (``examples.org``) is not."""
    if entry.get("kind") in BRAND_KINDS:
        return True
    head = ascii_name.split(".", 1)[0]
    return head == label or head.startswith(label + "-") or head.endswith("-" + label)


def assess_risk(entry: dict, today: date, brand: bool = False) -> str:
    """Impersonation risk of one registered look-alike.

    * ``high``: registered in the last :data:`RECENT_DAYS` days (RDAP), or a
      brand-intact look-alike (``brand``) with MX records, i.e. it can send
      mail that reads as yours;
    * ``medium``: any other look-alike with MX, or a brand-intact one that
      resolves to an address;
    * ``low``: everything else (parked, typo of another real word, ...).

    Certificate dates are NOT a recency signal: ACME certificates renew
    every 60-90 days on domains of any age. A new certificate is an event.
    """
    records = entry.get("records") or {}
    recent = _is_recent(entry.get("created") or "", today)
    resolves = bool(records.get("A") or records.get("AAAA"))
    if recent or (brand and records.get("MX")):
        return "high"
    if records.get("MX") or (brand and resolves):
        return "medium"
    return "low"


def load_state(path: Path) -> Optional[dict]:
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    if state.get("version") != STATE_VERSION:
        raise ValueError(f"{path}: unsupported state version {state.get('version')!r}")
    return state


def save_state(path: Path, state: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(state, indent=1, sort_keys=True), encoding="utf-8")
    tmp.replace(path)


def _cert_matches(
    cert_names: Iterable[str], keyword: str, owned: set, candidates: set
) -> list:
    """Look-alike names on a certificate: not ours, and either containing
    the brand keyword or equal to a generated candidate."""
    out = []
    for raw in cert_names:
        name = raw.lstrip("*.").lower()
        base = registrable_domain(name)
        if base is None or base in owned:
            continue
        if keyword in base or base in candidates:
            out.append(base)
    return sorted(set(out))


def watch_domain(
    domain: str,
    *,
    state_dir: Optional[Path] = None,
    owned: Sequence[str] = (),
    ct: bool = True,
    rdap: bool = True,
    query: Optional[QueryFn] = None,
    fetch: Optional[FetchFn] = None,
    now: Optional[datetime] = None,
    tlds: Sequence[str] = DEFAULT_TLDS,
    prefixes: Sequence[str] = DEFAULT_PREFIXES,
    suffixes: Sequence[str] = DEFAULT_SUFFIXES,
    workers: int = 32,
    ct_throttle: Optional[Throttle] = None,
    rdap_interval_s: float = 1.0,
) -> WatchReport:
    """Probe every look-alike of ``domain`` and diff against saved state.

    ``owned`` lists further domains that are yours (never reported). The
    state file is updated in place; pending (unsent) events are kept in it
    by :func:`watch_domains` until an alert is delivered.
    """
    domain = to_ascii(domain.strip().lower().rstrip(".")) or domain
    label, _tld = split_domain(domain)
    today = _today(now)
    stamp = (now or datetime.now(timezone.utc)).astimezone(timezone.utc).isoformat()
    state_dir = Path(state_dir) if state_dir else default_state_dir()
    path = state_dir / f"{domain}.json"
    previous = load_state(path)
    baseline = previous is None
    state = previous or {
        "version": STATE_VERSION,
        "domain": domain,
        "first_run": stamp,
        "names": {},
        "certs": {},
        "pending_events": [],
    }
    owned_set = {domain, *(registrable_domain(o) or o for o in owned)}
    report = WatchReport(domain, baseline, 0, state_path=str(path))

    candidates = generate_lookalike_domains(
        domain, tlds=tlds, prefixes=prefixes, suffixes=suffixes
    )
    by_ascii: dict = {c.ascii: c for c in candidates if c.ascii not in owned_set}
    report.candidates = len(by_ascii)

    # Certificate Transparency, prefix search on the brand label
    # (``example%``): catches names no generator thought of (example-pay.xyz).
    # crt.sh answers a LEADING wildcard (``%example%``) with an empty list,
    # silently, so only the prefix form is usable.
    ct_throttle = ct_throttle or Throttle(3.0)
    ct_cache = state_dir / "ct-cache"
    certs = []
    if ct:
        try:
            certs = search_certificates(
                f"{label}%", fetch=fetch, throttle=ct_throttle, cache_dir=ct_cache
            )
        except FetchError as exc:
            report.errors.append(f"crt.sh {label}%: {exc}")
    cert_hits: dict = {}  # registrable look-alike -> {cert id: Certificate}
    for cert in certs:
        for base in _cert_matches(cert.names, label, owned_set, set(by_ascii)):
            cert_hits.setdefault(base, {})[cert.id] = cert
    for base in cert_hits:
        by_ascii.setdefault(base, Candidate(base, base, "ct", "seen in CT logs"))

    query = query or dnspython_query()
    probes: dict = probe_domains(list(by_ascii), query=query, workers=workers)

    names = state["names"]
    previous_names = set(names)
    events: list = []
    registered_now = []
    for ascii_name, probe in probes.items():
        cand = by_ascii[ascii_name]
        prior = names.get(ascii_name)
        if probe.registered is None:
            report.errors.append(f"dns {ascii_name}: {probe.error}")
            continue
        if not probe.registered:
            if prior and prior.get("registered"):
                prior["registered"] = False
                prior["last_seen_unregistered"] = stamp
            continue
        registered_now.append(ascii_name)
        entry = _merge_entry(prior, cand, probe, stamp)
        names[ascii_name] = entry
        was_registered = bool(prior and prior.get("registered", True))
        # A name known only from CT logs is reported by its new-cert event;
        # its registration may be old (it was just never generated).
        if not baseline and not was_registered and cand.kind != "ct":
            events.append(("new-registration", ascii_name, _records_summary(probe)))
        old_mx = set((prior or {}).get("records", {}).get("MX") or [])
        new_mx = sorted(set(probe.records.get("MX") or []) - old_mx)
        if not baseline and new_mx and was_registered:
            events.append(("new-mx", ascii_name, "mx: " + ", ".join(new_mx)))

    if rdap:
        missing = [n for n in registered_now if "created" not in names[n]]
        for name, created in registration_dates(
            missing,
            fetch=fetch,
            interval_s=rdap_interval_s,
            cache_dir=state_dir / "rdap-cache",
        ).items():
            if created and created.startswith("error:"):
                report.errors.append(f"rdap {name}: {created[7:]}")
            else:
                names[name]["created"] = created

    # Certificate Transparency, exact name, for every registered look-alike:
    # cheap for crt.sh, and covers IDN (punycode) names a keyword never matches.
    # Names whose exact query never succeeded before have no certificate
    # baseline yet; their first successful query only records.
    unbaselined = {n for n, e in names.items() if not e.get("ct_checked")}
    if ct:
        for ascii_name in registered_now:
            try:
                found = search_certificates(
                    ascii_name, fetch=fetch, throttle=ct_throttle, cache_dir=ct_cache
                )
            except FetchError as exc:
                report.errors.append(f"crt.sh {ascii_name}: {exc}")
                continue
            names[ascii_name]["ct_checked"] = True
            for cert in found:
                cert_hits.setdefault(ascii_name, {})[cert.id] = cert

    # Only a look-alike's FIRST certificate is an event: ACME renewals of an
    # established site (every 60-90 days) are recorded, not alerted.
    seen_certs = state["certs"]
    certified_before = {c.get("lookalike") for c in seen_certs.values()}
    for base, by_id in cert_hits.items():
        entry = names.get(base)
        new_certs = []
        for cert in by_id.values():
            key = str(cert.id)
            if key in seen_certs:
                continue
            seen_certs[key] = {**cert.to_dict(), "lookalike": base, "first_seen": stamp}
            new_certs.append(cert)
            if entry is not None:
                entry["cert_dates"] = sorted(
                    {*entry.get("cert_dates", []), cert.not_before[:10]}
                )
        known_without_baseline = base in unbaselined and base in previous_names
        if (
            new_certs
            and not baseline
            and base not in certified_before
            and not known_without_baseline
        ):
            first = min(new_certs, key=lambda c: c.not_before)
            events.append(
                (
                    "new-cert",
                    base,
                    f"first cert {first.id} {first.not_before[:10]} {first.issuer[:60]}",
                )
            )

    for ascii_name in registered_now:
        entry = names[ascii_name]
        brand = is_brand_intact(entry, ascii_name, label)
        entry["risk"] = assess_risk(entry, today, brand)
    for kind, ascii_name, detail in events:
        entry = names.get(ascii_name) or {}
        risk = entry.get("risk") or ("high" if kind != "new-registration" else "low")
        display = entry.get("name") or by_ascii[ascii_name].name
        report.events.append(Event(kind, domain, display, detail, risk))

    report.hits = sorted(
        (_hit_row(n, names[n], seen_certs) for n in registered_now),
        key=lambda r: ({"high": 0, "medium": 1, "low": 2}[r["risk"]], r["ascii"]),
    )
    state["last_run"] = stamp
    state["pending_events"] = [
        *state.get("pending_events", []),
        *(asdict(e) for e in report.events),
    ]
    save_state(path, state)
    return report


def _merge_entry(
    prior: Optional[dict], cand: Candidate, probe: DomainProbe, stamp: str
):
    entry = dict(prior or {})
    entry.update(
        name=cand.name,
        kind=entry.get("kind", cand.kind),
        detail=entry.get("detail", cand.detail),
        registered=True,
        records=probe.records,
        last_seen=stamp,
    )
    entry.setdefault("first_seen", stamp)
    return entry


def _records_summary(probe: DomainProbe) -> str:
    parts = []
    for rtype in ("A", "MX", "NS"):
        values = probe.records.get(rtype) or []
        if values:
            parts.append(
                f"{rtype.lower()}: {', '.join(values[:2])}"
                + (" ..." if len(values) > 2 else "")
            )
    return "; ".join(parts) or "registered, no records"


def _hit_row(ascii_name: str, entry: dict, certs: dict) -> dict:
    records = entry.get("records") or {}
    n_certs = sum(1 for c in certs.values() if c.get("lookalike") == ascii_name)
    return {
        "name": entry.get("name", ascii_name),
        "ascii": ascii_name,
        "kind": entry.get("kind"),
        "a": records.get("A") or [],
        "aaaa": records.get("AAAA") or [],
        "mx": records.get("MX") or [],
        "ns": records.get("NS") or [],
        "created": entry.get("created"),
        "certs": n_certs,
        "risk": entry.get("risk", "low"),
    }


def pop_pending_events(state_dir: Optional[Path], domain: str) -> list:
    """Events of ``domain`` not yet delivered (as dicts), clearing them."""
    domain = to_ascii(domain.strip().lower().rstrip(".")) or domain
    path = (Path(state_dir) if state_dir else default_state_dir()) / f"{domain}.json"
    state = load_state(path)
    if not state:
        return []
    pending = state.get("pending_events", [])
    state["pending_events"] = []
    save_state(path, state)
    return pending


def peek_pending_events(state_dir: Optional[Path], domain: str) -> list:
    domain = to_ascii(domain.strip().lower().rstrip(".")) or domain
    path = (Path(state_dir) if state_dir else default_state_dir()) / f"{domain}.json"
    state = load_state(path)
    return list((state or {}).get("pending_events", []))


# EOF
