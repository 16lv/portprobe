# tcp-dns-diagnostics

Hostname validation, DNS resolution, and concurrent TCP port connectivity diagnostics written in **Python 3.12** using only the standard library (`socket`, `ipaddress`, `concurrent.futures`).

## Features

- **Input validation**: `validate_host()` verifies RFC-style hostnames and IPv4/IPv6 literals before opening sockets.
- **DNS inspection**: `resolve_dns()` measures lookup latency via `socket.getaddrinfo()` and handles `socket.gaierror` cleanly.
- **Concurrent TCP probing**: `build_diagnostic_report()` deduplicates ports while preserving order, validates bounds (`1..65535`), skips TCP probes when DNS fails, and probes ports concurrently with `ThreadPoolExecutor`.

## Structure

```text
tcp-dns-diagnostics/
├── src/net_diag/
│   └── diagnostics.py
├── tests/
│   └── test_diagnostics.py
├── pyproject.toml
└── requirements.txt
```

## Development

```bash
pip install -e ".[dev]"
ruff check .
pytest -v
```
