# TCP & DNS Diagnostics (tcp-dns-diagnostics)

![CI Status](https://github.com/16lv/tcp-dns-diagnostics/actions/workflows/ci.yml/badge.svg)

**TCP & DNS Diagnostics** ($(System.Collections.Hashtable.newRepo)) is a lightweight, cross-platform network connectivity and DNS troubleshooting utility written in **Python 3.12** using the standard library (`socket`, `ipaddress`, `time`).

## Why I Built It

When debugging a self-hosted service that won't load, `ping` is often unhelpful because cloud security groups drop ICMP echo packets, while a generic browser error hides whether DNS failed, a firewall dropped the packet, or the application process crashed. I built TCP & DNS Diagnostics to separate DNS resolution from per-port TCP three-way handshakes and classify each failure state clearly.

## Failure Classification

| Status | Underlying Socket Behaviour | Diagnostic Meaning |
| :--- | :--- | :--- |
| `RESOLVED` | `socket.getaddrinfo` succeeded | Hostname resolved to one or more IPv4/IPv6 addresses. |
| `DNS_FAILURE` | `socket.gaierror` raised | Domain does not exist (`NXDOMAIN`) or local resolver is unreachable. |
| `CONNECTED` | `socket.create_connection` succeeded | Full TCP three-way handshake (`SYN` -> `SYN-ACK` -> `ACK`) completed. |
| `CONNECTION_REFUSED` | `ConnectionRefusedError` (`ECONNREFUSED`) | Remote host is online and routing works, but sent a TCP `RST` because no process is listening on that port. |
| `TIMEOUT` | `TimeoutError` | No response within deadline; a firewall is likely dropping packets or the host is offline. |
| `UNREACHABLE` | `OSError` | Local network interface or routing table error. |

## Usage Example

```python
import json
from src.net_diag.diagnostics import build_diagnostic_report

report = build_diagnostic_report("shss7.agency", ports=[80, 443, 8080], timeout_seconds=2.5)
print(json.dumps(report, indent=2))
```

## Running Tests & Linter

All unit tests mock socket calls (`unittest.mock.patch`) so they run deterministically offline in milliseconds:

```bash
pip install -e ".[dev]"
ruff check .
pytest -v
```

## Known Limitations & Future Improvements

- `build_diagnostic_report` probes ports sequentially; using `asyncio.open_connection` would allow probing multiple ports concurrently when several ports time out.
