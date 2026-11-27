"""Tests for crt.sh / RDAP lookups with a real fake fetcher (no network)."""

import pytest
from _domain_fakes import BOOTSTRAP, FETCH_ERROR, IANA, FakeWeb, crt_row, rdap_payload

from scitex_security.domains._web import (
    FetchError,
    RateLimited,
    Throttle,
    rdap_bootstrap,
    registration_date,
    registration_dates,
    search_certificates,
)


def test_certificates_merge_rows_of_one_id():
    # Arrange
    web = FakeWeb({"https://crt.sh/": [crt_row(7, "a.test"), crt_row(7, "b.test")]})
    # Act
    certs = search_certificates("%test%", fetch=web)
    # Assert
    assert certs[0].names == ("a.test", "b.test")


def test_certificates_are_cached(tmp_path):
    # Arrange
    web = FakeWeb({"https://crt.sh/": [crt_row(7, "a.test")]})
    search_certificates("%test%", fetch=web, cache_dir=tmp_path)
    # Act
    search_certificates("%test%", fetch=web, cache_dir=tmp_path)
    # Assert
    assert len(web.urls) == 1


def test_certificate_query_excludes_expired():
    # Arrange
    web = FakeWeb({"https://crt.sh/": []})
    # Act
    search_certificates("%brand%", fetch=web)
    # Assert
    assert "exclude=expired" in web.urls[0]


def test_certificate_failure_retries_then_raises():
    # Arrange
    web = FakeWeb({"https://crt.sh/": FETCH_ERROR})
    # Act
    expected = FetchError
    # Assert
    with pytest.raises(expected):
        search_certificates("%brand%", fetch=web, retries=1)


BASES = {"com": "https://rdap.test/v1/"}


def test_bootstrap_maps_tlds_to_registry():
    # Arrange
    web = FakeWeb({IANA: BOOTSTRAP})
    # Act
    bases = rdap_bootstrap(fetch=web)
    # Assert
    assert bases["ai"] == "https://rdap.test/v1/"


def test_rdap_queries_the_registry_directly():
    # Arrange
    web = FakeWeb({"https://rdap.test/": rdap_payload("2026-01-01T00:00:00Z")})
    # Act
    registration_date("x.com", BASES, fetch=web)
    # Assert
    assert web.urls == ["https://rdap.test/v1/domain/x.com"]


def test_rdap_registration_date_is_a_utc_day():
    # Arrange
    web = FakeWeb({"https://rdap.test/": rdap_payload("2026-11-25T23:30:00-05:00")})
    # Act
    created = registration_date("x.com", BASES, fetch=web)
    # Assert
    assert created == "2026-11-26"


def test_rdap_for_tld_without_registry_is_none():
    # Arrange
    web = FakeWeb({})
    # Act
    created = registration_date("x.jp", BASES, fetch=web)
    # Assert
    assert created is None


def test_rdap_retries_once_after_429():
    # Arrange
    web = FakeWeb({"https://rdap.test/": RateLimited("HTTP 429")})
    slept = []
    # Act
    out = registration_dates(["x.com"], fetch=FakeWeb({IANA: BOOTSTRAP, **web.routes}),
                             interval_s=0, sleep=slept.append)  # fmt: skip
    # Assert
    assert (out["x.com"].startswith("error:"), slept) == (True, [10.0])


def test_rdap_bootstrap_failure_marks_every_name():
    # Arrange
    web = FakeWeb({IANA: FETCH_ERROR})
    # Act
    out = registration_dates(["a.com", "b.com"], fetch=web, interval_s=0)
    # Assert
    assert all(v.startswith("error:") for v in out.values())


def test_throttle_waits_for_the_interval():
    # Arrange
    clock = iter([0.0, 1.0, 5.0])
    slept = []
    throttle = Throttle(5.0, clock=lambda: next(clock), sleep=slept.append)
    throttle.wait()
    # Act
    throttle.wait()
    # Assert
    assert slept == [4.0]
