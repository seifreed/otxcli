<p align="center">
  <img src="https://img.shields.io/badge/otxcli-Threat%20Intelligence-blue?style=for-the-badge" alt="otxcli">
</p>

<h1 align="center">otxcli</h1>

<p align="center">
  <strong>Python library and CLI covering every endpoint of the AlienVault OTX v1 API</strong>
</p>

<p align="center">
  <a href="https://pypi.org/project/otxcli/"><img src="https://img.shields.io/pypi/v/otxcli?style=flat-square&logo=pypi&logoColor=white" alt="PyPI Version"></a>
  <a href="https://pypi.org/project/otxcli/"><img src="https://img.shields.io/pypi/pyversions/otxcli?style=flat-square&logo=python&logoColor=white" alt="Python Versions"></a>
  <a href="https://github.com/seifreed/otxcli/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License"></a>
</p>

<p align="center">
  <a href="https://github.com/seifreed/otxcli/stargazers"><img src="https://img.shields.io/github/stars/seifreed/otxcli?style=flat-square" alt="GitHub Stars"></a>
  <a href="https://github.com/seifreed/otxcli/issues"><img src="https://img.shields.io/github/issues/seifreed/otxcli?style=flat-square" alt="GitHub Issues"></a>
  <a href="https://buymeacoffee.com/seifreed"><img src="https://img.shields.io/badge/Buy%20Me%20a%20Coffee-support-yellow?style=flat-square&logo=buy-me-a-coffee&logoColor=white" alt="Buy Me a Coffee"></a>
</p>

---

## Overview

**otxcli** is a Python toolkit to query and manage threat intelligence on
[AlienVault OTX](https://otx.alienvault.com/). Every endpoint documented in the
[OTX v1 API](https://otx.alienvault.com/assets/static/external_api.html) is implemented:
indicator lookups, file/URL submissions, pulse management, search, and user actions —
usable both as a command-line tool and as a typed Python library.

### Key Features

| Feature | Description |
|---------|-------------|
| **Complete API coverage** | All 40 documented OTX v1 operations |
| **CLI + Library** | Use as command-line tool or Python package |
| **Indicator lookups** | IPv4, IPv6, domain, hostname, file hash, URL, CVE, NIDS, correlation rule — with every section |
| **Submissions** | Submit files and URLs for analysis, list them, manage their TLP |
| **Pulse management** | Create, edit, delete, subscribe, related pulses, feeds, events |
| **IDN aware** | Internationalized domains resolve via UTS46 punycode, the same rules a browser applies |
| **Clean errors** | `OTXError` with `status` and `detail`; CLI always exits 1 with a message, never a traceback |
| **Cross-platform** | Windows, Linux and macOS, x64 and ARM |
| **Battle-tested** | Integration suite runs against the live API with 100% coverage and no mocks |

### Supported Outputs

```text
CLI          Pretty-printed JSON on stdout, errors on stderr
Library      Decoded JSON (dict/list) per call, OTXError on failure
```

---

## Installation

### From PyPI (Recommended)

```bash
pip install otxcli
```

### From Source

```bash
git clone https://github.com/seifreed/otxcli.git
cd otxcli
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -e .
```

---

## Quick Start

Get an API key from your [OTX account settings](https://otx.alienvault.com/settings) and export it:

```bash
export OTX_API_KEY=your-key-here

# Validate your API key
otx me

# Look up an indicator
otx ipv4 8.8.8.8

# Search pulses
otx search-pulses zeus --limit 5
```

---

## Usage

### Command Line Interface

```bash
# Indicator sections
otx ipv4 8.8.8.8 --section reputation
otx domain rghost.net --section malware
otx file 6c5360d41bd2b14b1565f5b18e5c203cf512e493 --section analysis
otx url http://example.com/ --section url_list
otx cve CVE-2014-0160

# Submissions
otx submit-url http://example.com/ --tlp white
otx submit-file suspicious.bin
otx submitted-files --limit 10 --sort add_date

# Pulses
otx pulse 57204e9b3c4c3e015d93cb12
otx create-pulse '{"name": "My pulse", "public": true, "TLP": "white"}'
otx edit-pulse 57204e9b3c4c3e015d93cb12 '{"description": "New description"}'
otx subscribed-pulses --limit 10 --modified-since 2026-01-01T00:00:00+00:00

# Users
otx subscribe-to-user AlienVault
```

### Available Commands

| Command group | Commands |
|---------------|----------|
| **Indicators** | `ipv4`, `ipv6`, `domain`, `hostname`, `file`, `url`, `cve`, `nids`, `correlation-rule` |
| **Submissions** | `submit-file`, `submit-url`, `submit-urls`, `submitted-files`, `submitted-urls`, `update-submitted-files-tlp`, `update-submitted-urls-tlp` |
| **Pulses** | `pulse`, `create-pulse`, `edit-pulse`, `delete-pulse`, `pulse-indicators`, `pulse-related`, `related-pulses`, `subscribe-to-pulse`, `unsubscribe-from-pulse`, `subscribed-pulses`, `subscribed-pulse-ids`, `activity`, `events`, `my-pulses`, `user-pulses`, `indicator-types`, `validate-indicator` |
| **Search** | `search-pulses`, `search-users` |
| **Users** | `me`, `subscribe-to-user`, `unsubscribe-from-user`, `follow-user`, `unfollow-user` |

Run `otx --help` for the full list and `otx <command> --help` for the options of a
specific command.

### Global Options

| Option | Description |
|--------|-------------|
| `--api-key <key>` | OTX API key (defaults to the `OTX_API_KEY` environment variable) |
| `--server <host>` | API server host (defaults to `otx.alienvault.com`) |
| `--timeout <seconds>` | Request timeout in seconds (defaults to 120) |

---

## Python Library

### Basic Usage

```python
from otxcli import OTXClient

client = OTXClient("your-key-here")

client.me()
client.ipv4("8.8.8.8", section="reputation")
client.domain("rghost.net", section="malware")
client.search_pulses("zeus", limit=5)

pulse = client.create_pulse({"name": "My pulse", "public": True, "TLP": "white"})
client.edit_pulse(pulse["id"], {"description": "New description"})
client.delete_pulse(pulse["id"])
```

Every method returns the decoded JSON response, or `None` when the endpoint answers
with an empty body. HTTP errors and unparseable responses raise `otxcli.OTXError`,
which carries `status` and `detail` attributes.

### Internationalized Domains

`domain` and `hostname` accept internationalized names: OTX only resolves ASCII hosts,
so the name is converted to punycode with UTS46 mapping, the same rules a browser
applies. `client.domain("bücher.de")` looks up `xn--bcher-kva.de`, and a homograph such
as `ᴳoogle.com` reaches `google.com` rather than a lookalike nobody serves. ASCII
hostnames are sent exactly as given.

---

## Requirements

- Python 3.14+
- One runtime dependency: [`idna`](https://pypi.org/project/idna/) — see
  [pyproject.toml](pyproject.toml)

---

## Development

All dependencies (runtime and development) live in `pyproject.toml`:

```bash
pip install -e '.[dev]'
```

Quality and security gates, all of which must pass clean:

```bash
black --check .
ruff check .
mypy .
bandit -r .
pip-audit
```

Tests run against the live OTX API (no mocks) and require `OTX_API_KEY`:

```bash
export OTX_API_KEY=your-key-here
pytest
```

Coverage below 100% fails the build.

---

## Contributing

Contributions are welcome.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## Support the Project

If this project is useful in your workflows, you can support development:

<a href="https://buymeacoffee.com/seifreed" target="_blank">
  <img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" height="50">
</a>

---

## License

This project is licensed under the MIT license. See [LICENSE](LICENSE).

**Attribution**
- Author: **Marc Rivero López** | [@seifreed](https://github.com/seifreed)
- Repository: [github.com/seifreed/otxcli](https://github.com/seifreed/otxcli)

---

<p align="center">
  <sub>Built for practical threat intelligence workflows and security automation</sub>
</p>
