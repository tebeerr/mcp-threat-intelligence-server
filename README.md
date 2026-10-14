# Threat Intelligence MCP Server

A local, stdio-based MCP server for passive indicator lookups. The first
increment exposes `analyze_indicator` and uses AlienVault OTX; URLhaus,
ATT&CK data, and SQLite persistence are intentionally left for later steps.

## Requirements

- Python 3.12 or newer
- An AlienVault OTX API key for live lookups

## Install

```powershell
py -3.12 -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

Set configuration in the process environment. The API key is optional for
starting the server, but lookups return a source-unavailable result without it.

```powershell
$env:OTX_API_KEY = "your-otx-api-key"
```

Run the server over stdio:

```powershell
ti-mcp
```

The tool validates indicators before making any network request. Supported
values are IPv4, IPv6, domain names, HTTP(S) URLs, and SHA-256 hashes. Lookups
are passive; the server never connects to the submitted indicator.

## Tests

```powershell
python -m pytest
```

Connector tests use mock HTTP responses and do not contact external services.
