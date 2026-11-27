"""Tests for DNS probing with a real fake resolver (no network)."""

import os

import pytest
from _domain_fakes import FakeDNS

from scitex_security.domains._dns import probe_domain, probe_domains

ZONE = {
    "mail-example.com": {
        "A": ["192.0.2.10"],
        "MX": ["mx.mail-example.com"],
        "NS": ["ns1.parking.test"],
    },
    "parked-example.com": {"NS": ["ns1.parking.test"]},
}


def test_nxdomain_is_unregistered():
    # Arrange
    dns = FakeDNS(ZONE)
    # Act
    probe = probe_domain("free-example.com", dns)
    # Assert
    assert probe.registered is False


def test_nxdomain_stops_after_one_query():
    # Arrange
    dns = FakeDNS(ZONE)
    # Act
    probe_domain("free-example.com", dns)
    # Assert
    assert dns.calls == [("free-example.com", "A")]


def test_registered_name_collects_mx():
    # Arrange
    dns = FakeDNS(ZONE)
    # Act
    probe = probe_domain("mail-example.com", dns)
    # Assert
    assert probe.has_mx


def test_registered_name_without_address_does_not_resolve():
    # Arrange
    dns = FakeDNS(ZONE)
    # Act
    probe = probe_domain("parked-example.com", dns)
    # Assert
    assert (probe.registered, probe.resolves) == (True, False)


def test_lookup_failure_is_unknown_not_unregistered():
    # Arrange
    dns = FakeDNS(ZONE, failing={"mail-example.com"})
    # Act
    probe = probe_domain("mail-example.com", dns)
    # Assert
    assert probe.registered is None


def test_probe_domains_returns_every_name():
    # Arrange
    dns = FakeDNS(ZONE)
    names = ["mail-example.com", "free-example.com"]
    # Act
    probes = probe_domains(names, dns, workers=2)
    # Assert
    assert set(probes) == set(names)


@pytest.mark.skipif(
    os.environ.get("SCITEX_SECURITY_LIVE_TESTS") != "1",
    reason="live network smoke test; set SCITEX_SECURITY_LIVE_TESTS=1",
)
def test_live_dns_smoke_example_com_has_nameservers():
    # Arrange
    name = "example.com"
    # Act
    probe = probe_domain(name)
    # Assert
    assert probe.records.get("NS")
