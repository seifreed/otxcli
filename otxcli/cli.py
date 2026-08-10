"""Command line interface exposing every OTX v1 API endpoint."""

from __future__ import annotations

import argparse
import json
import os
import sys
from http.client import HTTPException
from pathlib import Path
from typing import Any

from otxcli.client import DEFAULT_SECTION, DEFAULT_SERVER, DEFAULT_TIMEOUT, OTXClient, OTXError

Arg = tuple[str, dict[str, Any]]


def json_object(text: str) -> dict[str, Any]:
    """Parse a JSON argument, rejecting payloads that are not objects."""
    value = json.loads(text)
    if not isinstance(value, dict):
        raise argparse.ArgumentTypeError(f"expected a JSON object, got {type(value).__name__}")
    return value


_SECTION: Arg = ("--section", {"default": DEFAULT_SECTION, "help": "Indicator section to fetch"})
_PAGING: list[Arg] = [
    ("--limit", {"type": int, "help": "Results per page"}),
    ("--page", {"type": int, "help": "Page number"}),
]
_SORT: Arg = ("--sort", {"help": "Sort field"})
_MODIFIED_SINCE: Arg = ("--modified-since", {"help": "ISO 8601 datetime lower bound"})
_SINCE: Arg = ("--since", {"help": "ISO 8601 datetime lower bound"})
_TLP: Arg = ("--tlp", {"help": "TLP level: white, green, amber or red"})
_TLP_REQUIRED: Arg = (_TLP[0], {**_TLP[1], "required": True})

COMMANDS: list[tuple[str, str, list[Arg]]] = [
    ("ipv4", "IPv4 address indicator details", [("ip", {}), _SECTION]),
    ("ipv6", "IPv6 address indicator details", [("ip", {}), _SECTION]),
    ("domain", "Domain indicator details", [("domain", {}), _SECTION]),
    ("hostname", "Hostname indicator details", [("hostname", {}), _SECTION]),
    ("file", "File hash indicator details", [("file_hash", {}), _SECTION]),
    ("url", "URL indicator details", [("url", {}), _SECTION]),
    ("cve", "CVE indicator details", [("cve", {}), _SECTION]),
    ("nids", "NIDS indicator details", [("nids", {}), _SECTION]),
    ("correlation-rule", "Correlation rule details", [("rule_id", {}), _SECTION]),
    ("submit-file", "Submit a file for analysis", [("path", {"help": "File to submit"})]),
    ("submitted-files", "List your submitted files", [*_PAGING, _SORT]),
    (
        "update-submitted-files-tlp",
        "Update the TLP of your submitted files",
        [("hashes", {"nargs": "+"}), _TLP_REQUIRED],
    ),
    ("submit-url", "Submit a URL for analysis", [("url", {}), _TLP]),
    ("submit-urls", "Submit multiple URLs for analysis", [("urls", {"nargs": "+"}), _TLP]),
    ("submitted-urls", "List your submitted URLs", [*_PAGING, _SORT]),
    (
        "update-submitted-urls-tlp",
        "Update the TLP of your submitted URLs",
        [("urls", {"nargs": "+"}), _TLP_REQUIRED],
    ),
    ("pulse", "Pulse details", [("pulse_id", {})]),
    (
        "edit-pulse",
        "Edit a pulse (changes is a JSON object)",
        [("pulse_id", {}), ("changes", {"type": json_object})],
    ),
    ("pulse-indicators", "Indicators inside a pulse", [("pulse_id", {}), *_PAGING]),
    ("pulse-related", "Pulses sharing indicators with a pulse", [("pulse_id", {}), *_PAGING]),
    (
        "related-pulses",
        "Pulses related to a pulse, malware family or adversary",
        [
            ("--pulse-id", {}),
            ("--malware-family", {}),
            ("--adversary", {}),
            *_PAGING,
        ],
    ),
    ("subscribed-pulses", "Your threat intelligence feed", [*_PAGING, _MODIFIED_SINCE]),
    ("subscribed-pulse-ids", "Ids of pulses you are subscribed to", _PAGING),
    ("activity", "Your activity feed", [*_PAGING, _MODIFIED_SINCE]),
    (
        "create-pulse",
        "Create a pulse (fields is a JSON object)",
        [("fields", {"type": json_object})],
    ),
    ("delete-pulse", "Delete a pulse you created", [("pulse_id", {})]),
    ("subscribe-to-pulse", "Subscribe to a pulse", [("pulse_id", {})]),
    ("unsubscribe-from-pulse", "Unsubscribe from a pulse", [("pulse_id", {})]),
    ("indicator-types", "List indicator types recognized by OTX", []),
    (
        "validate-indicator",
        "Validate an indicator:type pair",
        [("indicator_type", {}), ("indicator", {})],
    ),
    ("events", "Subscription and pulse events", [*_PAGING, _MODIFIED_SINCE]),
    ("user-pulses", "Pulses created by a user", [("username", {}), *_PAGING, _SINCE]),
    ("my-pulses", "Pulses you created", [*_PAGING, _SINCE]),
    ("search-pulses", "Search pulses", [("q", {}), *_PAGING, _SORT]),
    ("search-users", "Search users", [("q", {}), *_PAGING, _SORT]),
    ("me", "Validate your API key and show account details", []),
    ("subscribe-to-user", "Subscribe to a user", [("username", {})]),
    ("unsubscribe-from-user", "Unsubscribe from a user", [("username", {})]),
    ("follow-user", "Follow a user", [("username", {})]),
    ("unfollow-user", "Unfollow a user", [("username", {})]),
]

GLOBAL_OPTIONS: list[Arg] = [
    (
        "--api-key",
        {
            # Resolved against OTX_API_KEY in main(), at invocation time: a default captured
            # here would freeze the environment as it was when this module was imported.
            "default": None,
            "help": "OTX API key (defaults to the OTX_API_KEY environment variable)",
        },
    ),
    ("--server", {"default": DEFAULT_SERVER, "help": "API server host"}),
    (
        "--timeout",
        {"type": float, "default": DEFAULT_TIMEOUT, "help": "Request timeout in seconds"},
    ),
]

# Derived, so an option added above can never be forwarded to a client method by mistake.
_GLOBAL_ARGS = {
    "command",
    *(name.removeprefix("--").replace("-", "_") for name, _ in GLOBAL_OPTIONS),
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="otx", description="AlienVault OTX v1 API client")
    for arg_name, options in GLOBAL_OPTIONS:
        parser.add_argument(arg_name, **options)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name, help_text, args in COMMANDS:
        command = subparsers.add_parser(name, help=help_text)
        for arg_name, options in args:
            command.add_argument(arg_name, **options)
    return parser


def _method_kwargs(namespace: argparse.Namespace) -> dict[str, Any]:
    kwargs = {name: value for name, value in vars(namespace).items() if name not in _GLOBAL_ARGS}
    if namespace.command == "submit-file":
        path = Path(kwargs.pop("path"))
        kwargs = {"filename": path.name, "data": path.read_bytes()}
    return kwargs


def _invoke(namespace: argparse.Namespace) -> Any:
    client = OTXClient(namespace.api_key, namespace.server, namespace.timeout)
    method = getattr(client, namespace.command.replace("-", "_"))
    return method(**_method_kwargs(namespace))


def _print_result(result: Any) -> int:
    try:
        print(json.dumps(result, indent=2, sort_keys=True))
        sys.stdout.flush()
    except OSError:
        # stdout is gone: a closed pipe (`otx ... | head`) raises EPIPE on POSIX and EINVAL on
        # Windows. Point the file descriptor at devnull so the exit-time flush stays quiet,
        # without rebinding sys.stdout for the rest of the process.
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
        os.close(devnull)
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    namespace = build_parser().parse_args(argv)
    if namespace.api_key is None:
        namespace.api_key = os.environ.get("OTX_API_KEY", "")
    if not namespace.api_key:
        print("No API key: pass --api-key or set OTX_API_KEY", file=sys.stderr)
        return 1
    try:
        result = _invoke(namespace)
    except OTXError as error:
        print(str(error), file=sys.stderr)
        return 1
    except OSError as error:
        print(f"I/O error: {error}", file=sys.stderr)
        return 1
    except (HTTPException, ValueError, OverflowError) as error:
        print(f"Invalid request: {error}", file=sys.stderr)
        return 1
    return _print_result(result)
