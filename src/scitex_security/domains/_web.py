#!/usr/bin/env python3
# File: src/scitex_security/domains/_web.py

"""Certificate Transparency (crt.sh) and RDAP lookups, cached and rate-limited.

HTTP goes through an injected ``fetch(url, timeout) -> object`` (parsed
JSON), so tests pass a real fake. The default is stdlib ``urllib``.
"""

from __future__ import annotations

import hashlib
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable, Optional

FetchFn = Callable[[str, float], object]

USER_AGENT = "scitex-security-domains/1 (+https://github.com/scitex-ai/scitex-security)"
CRTSH_URL = "https://crt.sh/"
IANA_RDAP_BOOTSTRAP = "https://data.iana.org/rdap/dns.json"


class FetchError(RuntimeError):
    """An HTTP lookup failed; the caller reports it and carries on."""


class RateLimited(FetchError):
    """HTTP 429: the server asks us to slow down."""


def urllib_fetch(url: str, timeout: float = 60.0) -> object:
    """GET ``url`` and parse JSON. 404 returns None (no such object)."""
    request = urllib.request.Request(
        url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"}
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            body = response.read()
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        if exc.code == 429:
            raise RateLimited(f"{url}: HTTP 429") from exc
        raise FetchError(f"{url}: HTTP {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise FetchError(f"{url}: {type(exc).__name__}: {exc}") from exc
    if not body.strip():
        # An overloaded server answering 200 with nothing is a failure, not
        # "no results": treating it as empty would hide every certificate.
        raise FetchError(f"{url}: empty response body")
    try:
        return json.loads(body.decode("utf-8"))
    except ValueError as exc:
        raise FetchError(f"{url}: response is not JSON") from exc


class Throttle:
    """At most one request per ``interval_s`` per throttle (per host)."""

    def __init__(self, interval_s: float, clock=time.monotonic, sleep=time.sleep):
        self.interval_s = interval_s
        self._clock, self._sleep = clock, sleep
        self._last: Optional[float] = None

    def wait(self) -> None:
        if self._last is not None:
            remaining = self.interval_s - (self._clock() - self._last)
            if remaining > 0:
                self._sleep(remaining)
        self._last = self._clock()


# ------------------------------------------------------------------ CT ---


@dataclass(frozen=True)
class Certificate:
    """One crt.sh entry: a certificate id and the names it covers."""

    id: int
    names: tuple
    issuer: str
    not_before: str
    not_after: str
    logged_at: str

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "names": list(self.names),
            "issuer": self.issuer,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "logged_at": self.logged_at,
        }


def _cache_get(cache_dir: Optional[Path], key: str, ttl_s: float):
    if cache_dir is None:
        return None
    path = cache_dir / f"{hashlib.sha256(key.encode()).hexdigest()[:24]}.json"
    try:
        entry = json.loads(path.read_text())
    except (OSError, ValueError):
        return None
    if time.time() - float(entry.get("fetched_at", 0)) > ttl_s:
        return None
    return entry.get("data")


def _cache_put(cache_dir: Optional[Path], key: str, data) -> None:
    if cache_dir is None:
        return
    cache_dir.mkdir(parents=True, exist_ok=True)
    path = cache_dir / f"{hashlib.sha256(key.encode()).hexdigest()[:24]}.json"
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps({"key": key, "fetched_at": time.time(), "data": data}))
    tmp.replace(path)


def search_certificates(
    pattern: str,
    *,
    fetch: Optional[FetchFn] = None,
    cache_dir: Optional[Path] = None,
    cache_ttl_s: float = 6 * 3600.0,
    throttle: Optional[Throttle] = None,
    timeout: float = 90.0,
    retries: int = 1,
) -> list:
    """Unexpired certificates matching crt.sh identity ``pattern``.

    ``pattern`` is an exact name (``example-app.com``, fast) or a crt.sh
    prefix wildcard (``example%``: finds names nobody generated; slow, can
    take a minute). crt.sh answers a leading wildcard (``%example%``) with
    an empty list, so that form finds nothing. Non-empty results are cached for
    ``cache_ttl_s``; requests are spaced by ``throttle``; one retry is made
    before :class:`FetchError` propagates.
    """
    fetch = fetch or urllib_fetch
    query = urllib.parse.urlencode(
        {"q": pattern, "output": "json", "exclude": "expired"}
    )
    url = f"{CRTSH_URL}?{query}"
    rows = _cache_get(cache_dir, url, cache_ttl_s)
    if rows is None:
        last: Optional[Exception] = None
        for _attempt in range(retries + 1):
            if throttle:
                throttle.wait()
            try:
                rows = fetch(url, timeout) or []
                break
            except FetchError as exc:
                last = exc
        else:
            raise last  # type: ignore[misc]
        if rows:  # an empty answer is cheap to re-ask and may be transient
            _cache_put(cache_dir, url, rows)
    by_id: dict = {}
    for row in rows if isinstance(rows, list) else []:
        try:
            cert_id = int(row["id"])
        except (KeyError, TypeError, ValueError):
            continue
        names = {
            n.strip().lower()
            for field_ in ("common_name", "name_value")
            for n in str(row.get(field_) or "").splitlines()
            if n.strip()
        }
        prior = by_id.get(cert_id)
        if prior:
            names |= set(prior.names)
        by_id[cert_id] = Certificate(
            id=cert_id,
            names=tuple(sorted(names)),
            issuer=str(row.get("issuer_name") or ""),
            not_before=str(row.get("not_before") or ""),
            not_after=str(row.get("not_after") or ""),
            logged_at=str(row.get("entry_timestamp") or ""),
        )
    return sorted(by_id.values(), key=lambda c: c.id)


# ---------------------------------------------------------------- RDAP ---


def _parse_rdap_date(value: str) -> Optional[str]:
    try:
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError):
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).date().isoformat()


def rdap_bootstrap(
    *,
    fetch: Optional[FetchFn] = None,
    cache_dir: Optional[Path] = None,
    cache_ttl_s: float = 7 * 86400.0,
) -> dict:
    """``{tld: rdap base url}`` from IANA's RDAP bootstrap registry (RFC 9224).

    Querying each registry directly spreads the load; a shared redirector
    rate-limits a few dozen lookups. Cached for a week. Raises
    :class:`FetchError`.
    """
    fetch = fetch or urllib_fetch
    data = _cache_get(cache_dir, IANA_RDAP_BOOTSTRAP, cache_ttl_s)
    if data is None:
        data = fetch(IANA_RDAP_BOOTSTRAP, 30.0)
        if not isinstance(data, dict):
            raise FetchError(f"{IANA_RDAP_BOOTSTRAP}: no bootstrap data")
        _cache_put(cache_dir, IANA_RDAP_BOOTSTRAP, data)
    bases = {}
    for service in data.get("services") or []:
        try:
            tlds, urls = service[0], service[1]
        except (IndexError, TypeError):
            continue
        https = [u for u in urls if str(u).startswith("https://")] or list(urls)
        if https:
            base = str(https[0])
            for tld in tlds:
                bases[str(tld).lower()] = base if base.endswith("/") else base + "/"
    return bases


def registration_date(
    name: str,
    bases: dict,
    *,
    fetch: Optional[FetchFn] = None,
    throttle: Optional[Throttle] = None,
    timeout: float = 20.0,
    backoff_s: float = 10.0,
    sleep=time.sleep,
) -> Optional[str]:
    """RDAP ``registration`` event date (``YYYY-MM-DD``) of ``name``.

    None when the TLD's registry publishes no RDAP (absent from ``bases``)
    or the record has no registration event. One retry after ``backoff_s``
    on HTTP 429. Raises :class:`FetchError`.
    """
    fetch = fetch or urllib_fetch
    base = bases.get(name.rsplit(".", 1)[-1].lower())
    if base is None:
        return None
    url = base + "domain/" + urllib.parse.quote(name)
    for attempt in range(2):
        if throttle:
            throttle.wait()
        try:
            data = fetch(url, timeout)
            break
        except RateLimited:
            if attempt:
                raise
            sleep(backoff_s)
    if not isinstance(data, dict):
        return None
    for event in data.get("events") or []:
        if isinstance(event, dict) and event.get("eventAction") == "registration":
            return _parse_rdap_date(str(event.get("eventDate", "")))
    return None


def registration_dates(
    names: Iterable[str],
    *,
    fetch: Optional[FetchFn] = None,
    interval_s: float = 1.0,
    cache_dir: Optional[Path] = None,
    sleep=time.sleep,
) -> dict:
    """``{name: date-or-None}``; failures map to ``"error: ..."``.

    Requests are spaced ``interval_s`` apart per registry server.
    """
    names = list(names)
    if not names:
        return {}
    try:
        bases = rdap_bootstrap(fetch=fetch, cache_dir=cache_dir)
    except FetchError as exc:
        return {name: f"error: {exc}" for name in names}
    throttles: dict = {}
    out = {}
    for name in names:
        base = bases.get(name.rsplit(".", 1)[-1].lower(), "")
        throttle = throttles.setdefault(
            urllib.parse.urlsplit(base).netloc, Throttle(interval_s, sleep=sleep)
        )
        try:
            out[name] = registration_date(
                name, bases, fetch=fetch, throttle=throttle, sleep=sleep
            )
        except FetchError as exc:
            out[name] = f"error: {exc}"
    return out


# EOF
