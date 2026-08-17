"""CLI and Python library for the AlienVault OTX v1 API."""

from otxcli.client import (
    DEFAULT_SECTION,
    DEFAULT_SERVER,
    DEFAULT_TIMEOUT,
    OTXClient,
    OTXError,
)

__version__ = "0.1.2"
__all__ = [
    "DEFAULT_SECTION",
    "DEFAULT_SERVER",
    "DEFAULT_TIMEOUT",
    "OTXClient",
    "OTXError",
    "__version__",
]
