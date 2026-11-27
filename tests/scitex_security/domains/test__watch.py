"""Tests for the stateful watch: baseline, new registration, new MX, new cert."""

from datetime import datetime, timezone

from _domain_fakes import (
    BOOTSTRAP,
    FETCH_ERROR,
    IANA,
    FakeDNS,
    FakeWeb,
    crt_row,
    rdap_payload,
)

from scitex_security.domains._watch import (
    assess_risk,
    is_brand_intact,
    load_state,
    peek_pending_events,
    pop_pending_events,
    watch_domain,
)
from scitex_security.domains._web import Throttle

NOW = datetime(2026, 11, 27, tzinfo=timezone.utc)
SMALL = dict(
    tlds=("com",),
    prefixes=("get",),
    suffixes=("app",),
    now=NOW,
    ct_throttle=Throttle(0.0),
)


def _web(certs=(), created="2020-01-01T00:00:00Z"):
    return FakeWeb(
        {
            "https://crt.sh/": list(certs),
            IANA: BOOTSTRAP,
            "https://rdap.test/": rdap_payload(created),
        }
    )


def _run(tmp_path, zone, web=None, **kw):
    return watch_domain(
        "example.ai",
        state_dir=tmp_path,
        query=FakeDNS(zone),
        fetch=web or _web(),
        rdap_interval_s=0,
        **{**SMALL, **kw},
    )


def test_first_run_is_a_baseline_without_events(tmp_path):
    # Arrange
    zone = {"example.com": {"A": ["192.0.2.1"]}}
    # Act
    report = _run(tmp_path, zone)
    # Assert
    assert (report.baseline, report.events) == (True, [])


def test_first_run_reports_registered_lookalikes(tmp_path):
    # Arrange
    zone = {"example.com": {"A": ["192.0.2.1"]}}
    # Act
    report = _run(tmp_path, zone)
    # Assert
    assert [h["ascii"] for h in report.hits] == ["example.com"]


def test_new_registration_raises_event(tmp_path):
    # Arrange
    _run(tmp_path, {})
    # Act
    report = _run(tmp_path, {"getexample.ai": {"NS": ["ns.test"]}})
    # Assert
    assert [(e.kind, e.name) for e in report.events] == [
        ("new-registration", "getexample.ai")
    ]


def test_unchanged_lookalike_raises_nothing(tmp_path):
    # Arrange
    zone = {"example.com": {"A": ["192.0.2.1"]}}
    _run(tmp_path, zone)
    # Act
    report = _run(tmp_path, zone)
    # Assert
    assert report.events == []


def test_new_mx_on_known_lookalike_raises_event(tmp_path):
    # Arrange
    _run(tmp_path, {"example.com": {"A": ["192.0.2.1"]}})
    zone = {"example.com": {"A": ["192.0.2.1"], "MX": ["mx.evil.test"]}}
    # Act
    report = _run(tmp_path, zone)
    # Assert
    assert [(e.kind, e.risk) for e in report.events] == [("new-mx", "high")]


def test_new_certificate_raises_event(tmp_path):
    # Arrange
    zone = {"example-login.com": {"A": ["192.0.2.9"]}}
    _run(tmp_path, zone, ct=False)  # baseline without CT (and its cache)
    web = _web(certs=[crt_row(42, "example-login.com")])
    # Act
    report = _run(tmp_path, zone, web=web)
    # Assert
    assert [(e.kind, e.name) for e in report.events] == [
        ("new-cert", "example-login.com")
    ]


def test_certificates_for_owned_domains_are_ignored(tmp_path):
    # Arrange
    web = _web(certs=[crt_row(1, "www.example.ai"), crt_row(2, "x.example.net")])
    # Act
    report = _run(tmp_path, {}, web=web, owned=["example.net"])
    # Assert
    assert report.hits == []


def test_ct_failure_is_reported_not_raised(tmp_path):
    # Arrange
    web = FakeWeb({"https://crt.sh/": FETCH_ERROR})
    # Act
    report = _run(tmp_path, {}, web=web)
    # Assert
    assert report.errors[0].startswith("crt.sh example%:")


def test_rdap_date_is_stored(tmp_path):
    # Arrange
    zone = {"example.com": {"A": ["192.0.2.1"]}}
    # Act
    _run(tmp_path, zone, web=_web(created="2026-11-20T00:00:00Z"))
    # Assert
    state = load_state(tmp_path / "example.ai.json")
    assert state["names"]["example.com"]["created"] == "2026-11-20"


def test_events_stay_pending_until_popped(tmp_path):
    # Arrange
    _run(tmp_path, {})
    _run(tmp_path, {"getexample.ai": {"NS": ["ns.test"]}})
    pop_pending_events(tmp_path, "example.ai")
    # Act
    pending = peek_pending_events(tmp_path, "example.ai")
    # Assert
    assert pending == []


def test_recent_registration_is_high_risk():
    # Arrange
    entry = {"records": {"NS": ["ns.test"]}, "created": "2026-11-01"}
    # Act
    risk = assess_risk(entry, NOW.date())
    # Assert
    assert risk == "high"


def test_old_resolving_registration_is_medium_risk():
    # Arrange
    entry = {"kind": "tld-swap", "records": {"A": ["192.0.2.1"]}, "created": "2015"}
    # Act
    risk = assess_risk(entry, NOW.date(), brand=True)
    # Assert
    assert risk == "medium"


def test_old_typo_with_mx_is_medium_risk():
    # Arrange
    entry = {"kind": "omission", "records": {"MX": ["mx.test"]}, "created": "1999"}
    # Act
    risk = assess_risk(entry, NOW.date())
    # Assert
    assert risk == "medium"


def test_brand_lookalike_with_mx_is_high_risk():
    # Arrange
    entry = {"kind": "affix", "records": {"MX": ["mx.test"]}, "created": "2015"}
    # Act
    risk = assess_risk(entry, NOW.date(), brand=True)
    # Assert
    assert risk == "high"


def test_registered_lookalike_gets_an_exact_ct_query(tmp_path):
    # Arrange
    web = _web()
    # Act
    _run(tmp_path, {"getexample.ai": {"NS": ["ns.test"]}}, web=web)
    # Assert
    assert any("q=getexample.ai&" in url for url in web.urls)


def test_recent_certificate_alone_is_not_high_risk():
    # Arrange
    entry = {"kind": "omission", "records": {"A": ["192.0.2.1"]},
             "created": "2001-01-01", "cert_dates": ["2026-11-20"]}  # fmt: skip
    # Act
    risk = assess_risk(entry, NOW.date())
    # Assert
    assert risk == "low"


def test_ct_name_with_brand_label_is_brand_intact():
    # Arrange
    entry = {"kind": "ct"}
    # Act
    brand = is_brand_intact(entry, "example.de", "example")
    # Assert
    assert brand


def test_ct_name_with_longer_word_is_not_brand_intact():
    # Arrange
    entry = {"kind": "ct"}
    # Act
    brand = is_brand_intact(entry, "examples.org", "example")
    # Assert
    assert not brand


def test_certificate_renewal_is_not_an_event(tmp_path):
    # Arrange
    zone = {"example.com": {"A": ["192.0.2.1"]}}
    _run(tmp_path, zone, web=_web(certs=[crt_row(1, "example.com")]))
    renewed = _web(certs=[crt_row(1, "example.com"), crt_row(2, "example.com")])
    # Act
    report = _run(tmp_path, zone, web=renewed)
    # Assert
    assert report.events == []


def test_first_successful_ct_check_of_known_name_only_records(tmp_path):
    # Arrange
    zone = {"example.com": {"A": ["192.0.2.1"]}}
    _run(tmp_path, zone, ct=False)
    # Act
    report = _run(tmp_path, zone, web=_web(certs=[crt_row(5, "example.com")]))
    # Assert
    assert report.events == []
