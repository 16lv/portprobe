# Network Diagnostic Toolkit (Python)

A lightweight, cross-platform network connectivity and DNS troubleshooting utility written in **Python 3.12** using the standard library (`socket`, `ipaddress`, `time`).

## Overview

`network-diagnostic-toolkit` helps diagnose common connectivity issues on hosts and services you own or are permitted to test. Instead of treating every connection failure as identical, it distinguishes between:
- **DNS Resolution Failure (`DNS_FAILURE`):** `socket.getaddrinfo` cannot resolve the hostname.
- **Packet Drop / Timeout (`TIMEOUT`):** No SYN-ACK or RST received within the configured deadline.
- **Connection Refused (`CONNECTION_REFUSED`):** The remote host is online and reachable, but sent a TCP RST because no process is listening on that port.
- **Network Unreachable (`UNREACHABLE`):** Local routing or interface error.

## Running Tests & Linter

All unit tests mock socket calls so they run deterministically without making external network requests:

```bash
ruff check .
pytest -v
```
