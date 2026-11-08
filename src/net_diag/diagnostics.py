from __future__ import annotations

import ipaddress
import re
import socket
import time
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any

HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)


@dataclass(frozen=True)
class DnsCheckResult:
    host: str
    resolved: bool
    addresses: list[str]
    elapsed_ms: float
    status: str
    explanation: str


@dataclass(frozen=True)
class TcpProbeResult:
    host: str
    port: int
    reachable: bool
    elapsed_ms: float
    status: str
    explanation: str


def validate_host(host: str) -> str:
    # Check if it's a valid IPv4/IPv6 literal first, otherwise validate as a hostname
    cleaned = host.strip()
    if not cleaned:
        raise ValueError("Host must not be empty")
    try:
        ipaddress.ip_address(cleaned)
        return cleaned
    except ValueError:
        pass

    if not HOSTNAME_RE.match(cleaned):
        raise ValueError(f"Invalid hostname or IP address: '{host}'")
    return cleaned


def resolve_dns(host: str) -> DnsCheckResult:
    cleaned = validate_host(host)
    t0 = time.perf_counter()
    try:
        infos = socket.getaddrinfo(cleaned, None, type=socket.SOCK_STREAM)
        elapsed = (time.perf_counter() - t0) * 1000.0
        addrs = sorted({str(info[4][0]) for info in infos})
        return DnsCheckResult(
            host=cleaned,
            resolved=True,
            addresses=addrs,
            elapsed_ms=round(elapsed, 2),
            status="RESOLVED",
            explanation=f"Resolved {len(addrs)} address(es) via system resolver.",
        )
    except socket.gaierror as exc:
        elapsed = (time.perf_counter() - t0) * 1000.0
        return DnsCheckResult(
            host=cleaned,
            resolved=False,
            addresses=[],
            elapsed_ms=round(elapsed, 2),
            status="DNS_FAILURE",
            explanation=f"DNS lookup failed ({exc}). Check domain spelling or local DNS resolver.",
        )


def check_tcp_connectivity(
    host: str,
    port: int,
    timeout_seconds: float = 3.0,
) -> TcpProbeResult:
    cleaned = validate_host(host)
    if not (1 <= port <= 65535):
        raise ValueError(f"Port must be between 1 and 65535 (got {port})")
    if timeout_seconds <= 0:
        raise ValueError("Timeout must be positive")

    t0 = time.perf_counter()
    try:
        with socket.create_connection((cleaned, port), timeout=timeout_seconds):
            elapsed = (time.perf_counter() - t0) * 1000.0
            return TcpProbeResult(
                host=cleaned,
                port=port,
                reachable=True,
                elapsed_ms=round(elapsed, 2),
                status="CONNECTED",
                explanation=f"TCP three-way handshake succeeded on port {port}.",
            )
    except TimeoutError:
        elapsed = (time.perf_counter() - t0) * 1000.0
        return TcpProbeResult(
            host=cleaned,
            port=port,
            reachable=False,
            elapsed_ms=round(elapsed, 2),
            status="TIMEOUT",
            explanation=(
                f"Connection timed out after {timeout_seconds:.1f}s. "
                "A firewall may be dropping packets or the host is offline."
            ),
        )
    except ConnectionRefusedError:
        elapsed = (time.perf_counter() - t0) * 1000.0
        return TcpProbeResult(
            host=cleaned,
            port=port,
            reachable=False,
            elapsed_ms=round(elapsed, 2),
            status="CONNECTION_REFUSED",
            explanation=(
                f"Host is online and reachable, but no service is listening on TCP port {port} (RST received)."
            ),
        )
    except OSError as exc:
        elapsed = (time.perf_counter() - t0) * 1000.0
        return TcpProbeResult(
            host=cleaned,
            port=port,
            reachable=False,
            elapsed_ms=round(elapsed, 2),
            status="UNREACHABLE",
            explanation=f"Network or routing error: {exc}",
        )


def build_diagnostic_report(
    host: str,
    ports: list[int],
    timeout_seconds: float = 3.0,
) -> dict[str, Any]:
    dns_result = resolve_dns(host)
    # Use the validated hostname from dns_result and skip TCP probes if DNS failed
    if dns_result.resolved:
        tcp_results = [
            check_tcp_connectivity(dns_result.host, port, timeout_seconds=timeout_seconds)
            for port in ports
        ]
    else:
        tcp_results = [
            TcpProbeResult(
                host=dns_result.host,
                port=port,
                reachable=False,
                elapsed_ms=0.0,
                status="SKIPPED_DNS_FAILURE",
                explanation="Skipped TCP handshake because hostname resolution failed.",
            )
            for port in ports
        ]
    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "target_host": dns_result.host,
        "dns": asdict(dns_result),
        "tcp_checks": [asdict(r) for r in tcp_results],
        "note": (
            "Note: ICMP echo (ping) is often filtered by firewalls; TCP handshake checks "
            "provide a more reliable indicator of service availability on specific ports."
        ),
    }
