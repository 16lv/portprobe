from __future__ import annotations

import socket
from unittest.mock import MagicMock, patch

import pytest

from src.net_diag.diagnostics import (
    build_diagnostic_report,
    check_tcp_connectivity,
    resolve_dns,
    validate_host,
)


def test_validate_host_accepts_valid_domains_and_ips_and_rejects_invalid() -> None:
    assert validate_host("cardiff.ac.uk") == "cardiff.ac.uk"
    assert validate_host("127.0.0.1") == "127.0.0.1"

    with pytest.raises(ValueError):
        validate_host("")
    with pytest.raises(ValueError):
        validate_host("-invalid-hostname-.com")


def test_resolve_dns_handles_success_and_gaierror() -> None:
    fake_addrinfo = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
    ]
    with patch("socket.getaddrinfo", return_value=fake_addrinfo):
        res = resolve_dns("example.com")
        assert res.resolved is True
        assert res.addresses == ["93.184.216.34"]
        assert res.status == "RESOLVED"

    with patch("socket.getaddrinfo", side_effect=socket.gaierror("NXDOMAIN")):
        fail = resolve_dns("nonexistent.example.invalid")
        assert fail.resolved is False
        assert fail.status == "DNS_FAILURE"


def test_tcp_connectivity_distinguishes_connected_timeout_and_refused() -> None:
    mock_conn = MagicMock()
    with patch("socket.create_connection", return_value=mock_conn):
        ok = check_tcp_connectivity("example.com", 443)
        assert ok.reachable is True
        assert ok.status == "CONNECTED"

    with patch("socket.create_connection", side_effect=TimeoutError()):
        timed_out = check_tcp_connectivity("example.com", 443, timeout_seconds=1.0)
        assert timed_out.reachable is False
        assert timed_out.status == "TIMEOUT"

    with patch("socket.create_connection", side_effect=ConnectionRefusedError()):
        refused = check_tcp_connectivity("example.com", 8080)
        assert refused.reachable is False
        assert refused.status == "CONNECTION_REFUSED"


def test_build_diagnostic_report_aggregates_dns_and_tcp_checks() -> None:
    fake_addrinfo = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0)),
    ]
    with (
        patch("socket.getaddrinfo", return_value=fake_addrinfo),
        patch("socket.create_connection", return_value=MagicMock()),
    ):
        report = build_diagnostic_report("localhost", [80, 443])
        assert report["dns"]["resolved"] is True
        assert len(report["tcp_checks"]) == 2
        assert report["tcp_checks"][0]["status"] == "CONNECTED"
