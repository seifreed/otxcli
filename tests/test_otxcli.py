"""Integration tests for otxcli against the live OTX API. No mocks are used."""

from __future__ import annotations

import argparse
import copy
import hashlib
import inspect
import io
import json
import os
import sys
import tempfile
import time
import unittest
from collections.abc import Callable
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Any

from otxcli import OTXClient, OTXError
from otxcli.cli import COMMANDS, _method_kwargs, build_parser, json_object, main
from otxcli.client import _decode, _idna, _path

API_KEY = os.environ["OTX_API_KEY"]
BAD_KEY = "definitely-not-a-valid-key"
FILE_CONTENT = b"otxcli integration test file\n"
FILE_SHA256 = hashlib.sha256(FILE_CONTENT).hexdigest()
TEST_URL = "http://example.com/"
PULSE_FIELDS: dict[str, Any] = {
    "name": "otxcli integration test watchlist",
    "public": False,
    "TLP": "white",
    "indicators": [
        {
            "indicator": "otxcli_integration_test_mutex",
            "type": "Mutex",
            "description": "otxcli test artifact",
        }
    ],
}

# Retry budget: OTX is flaky enough to need retries (its pulse-feed endpoints 502 for
# stretches of many minutes), but a sick endpoint must not stall the suite forever. Worst
# case per call is ATTEMPTS * TIMEOUT + 62s of backoff, about five and a half minutes.
TIMEOUT = 45.0
ATTEMPTS = 6

client = OTXClient(API_KEY, timeout=TIMEOUT)
_known_pulse_id = ""


def backoff(attempt: int) -> None:
    """Wait between attempts, but never after the last one."""
    if attempt < ATTEMPTS - 1:
        time.sleep(2.0 * 2**attempt)


def call(func: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    """Invoke an API method, retrying server errors and network failures."""
    failure: Exception = OTXError(0, "no attempts made")
    for attempt in range(ATTEMPTS):
        try:
            return func(*args, **kwargs)
        except OTXError as error:
            if error.status < 500:
                raise
            failure = error
        except OSError as error:
            failure = error
        backoff(attempt)
    raise failure


def known_pulse_id() -> str:
    """Return the id of a long-lived public pulse to run read-only tests against."""
    global _known_pulse_id
    if not _known_pulse_id:
        found = call(client.search_pulses, "zeus", limit=1, sort="modified")
        _known_pulse_id = str(found["results"][0]["id"])
    return _known_pulse_id


def run_cli(*args: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main(list(args))
    return code, out.getvalue(), err.getvalue()


def run_cli_ok(*args: str) -> str:
    """Run a CLI command, retrying server-side failures, and return stdout."""
    err = ""
    for attempt in range(ATTEMPTS):
        code, out, err = run_cli("--timeout", str(TIMEOUT), *args)
        if code == 0:
            return out
        backoff(attempt)
    raise AssertionError(f"CLI command kept failing: {err}")


def run_cli_expecting_failure(expected: str, *args: str) -> str:
    """Run a CLI command that must fail for the expected reason, and return stderr.

    Retries outcomes that do not match: a transient 504 or a network hang would otherwise
    masquerade as the failure under test, or hide it entirely.
    """
    err = ""
    for attempt in range(ATTEMPTS):
        code, _, err = run_cli(*args)
        if code == 1 and expected in err:
            return err
        backoff(attempt)
    raise AssertionError(f"expected a failure mentioning {expected!r}, got: {err}")


# Indicator types whose lookup returns the very indicator that was asked for.
ECHOING_INDICATORS: list[tuple[str, str, str]] = [
    ("ipv4", "8.8.8.8", "8.8.8.8"),
    ("ipv6", "2001:4860:4860::8888", "2001:4860:4860:0:0:0:0:8888"),
    ("domain", "rghost.net", "rghost.net"),
    ("hostname", "mail.vspcord.com", "mail.vspcord.com"),
    ("cve", "CVE-2014-0160", "CVE-2014-0160"),
]

# Every distinct way the CLI can fail, and the wording it must use to explain itself.
CLI_FAILURES: list[tuple[str, list[str], str]] = [
    ("rejected api key", ["--api-key", BAD_KEY, "me"], "HTTP 403"),
    ("unreadable file", ["submit-file", "/nonexistent/otxcli-no-such-file"], "I/O error"),
    ("no api key at all", ["--api-key", "", "me"], "No API key"),
    ("unusable server", ["--api-key", API_KEY, "--server", "bad host", "me"], "Invalid request"),
    ("timeout out of range", ["--api-key", API_KEY, "--timeout", "1e30", "me"], "Invalid request"),
    ("newline in api key", ["--api-key", "key\nX-Injected: 1", "me"], "Invalid request"),
]


class IndicatorLookupTests(unittest.TestCase):
    def test_lookups_echo_the_indicator(self) -> None:
        """These types answer with the indicator that was asked for, IPv6 in expanded form."""
        for name, asked, echoed in ECHOING_INDICATORS:
            with self.subTest(name):
                self.assertEqual(call(getattr(client, name), asked)["indicator"], echoed)

    def test_ipv4_reputation_section(self) -> None:
        self.assertIn("reputation", call(client.ipv4, "8.8.8.8", section="reputation"))

    def test_internationalized_domain_resolves_via_punycode(self) -> None:
        result = call(client.domain, "bücher.de")
        self.assertEqual(result["indicator"], "xn--bcher-kva.de")

    def test_file(self) -> None:
        result = call(client.file, "6c5360d41bd2b14b1565f5b18e5c203cf512e493")
        self.assertIn("indicator", result)

    def test_url(self) -> None:
        target = "http://www.fotoidea.com/sport/4x4_san_ponso/slides/IMG_0068.html"
        self.assertIn("indicator", call(client.url, target))

    def test_nids(self) -> None:
        self.assertIsInstance(call(client.nids, "2820184"), dict)

    def test_correlation_rule(self) -> None:
        result = call(client.correlation_rule, "572f8c3c540c6f0161677877")
        self.assertIsInstance(result, dict)

    def test_indicator_types(self) -> None:
        names = [entry["name"] for entry in call(client.indicator_types)["detail"]]
        self.assertIn("IPv4", names)

    def test_validate_indicator(self) -> None:
        result = call(client.validate_indicator, "IPv4", "8.8.8.8")
        self.assertEqual(result["status"], "success")


class SubmissionTests(unittest.TestCase):
    def test_url_submission_flow(self) -> None:
        self.assertEqual(call(client.submit_url, TEST_URL, tlp="white")["status"], "ok")
        bulk = call(client.submit_urls, [TEST_URL, "http://example.org/"], tlp="white")
        self.assertEqual(bulk["status"], "ok")
        listed = call(client.submitted_urls, limit=1, page=1, sort="add_date")
        self.assertIn("results", listed)
        updated = call(client.update_submitted_urls_tlp, [TEST_URL], "white")
        self.assertEqual(updated["status"], "ok")

    def test_file_submission_flow(self) -> None:
        submitted = call(client.submit_file, "otxcli_test.txt", FILE_CONTENT)
        self.assertEqual(submitted["status"], "ok")
        self.assertEqual(submitted["sha256"], FILE_SHA256)
        listed = call(client.submitted_files, limit=1, page=1, sort="add_date")
        self.assertIn("results", listed)
        updated = call(client.update_submitted_files_tlp, [FILE_SHA256], "white")
        self.assertEqual(updated["status"], "ok")


class PulseReadTests(unittest.TestCase):
    def test_search_and_read_pulse(self) -> None:
        pulse_id = known_pulse_id()
        self.assertEqual(call(client.pulse, pulse_id)["id"], pulse_id)
        self.assertIn("results", call(client.pulse_indicators, pulse_id, limit=5, page=1))
        self.assertIn("results", call(client.pulse_related, pulse_id, limit=5, page=1))
        related = call(client.related_pulses, pulse_id=pulse_id, limit=5, page=1)
        self.assertIn("results", related)

    def test_related_pulses_by_malware_family(self) -> None:
        result = call(client.related_pulses, malware_family="Virus:Win32/Nabucur", limit=1)
        self.assertIn("results", result)

    def test_feeds(self) -> None:
        """Each feed is its own subtest, so one sick endpoint cannot mask the others."""
        for name in ("subscribed_pulses", "subscribed_pulse_ids", "activity", "events"):
            with self.subTest(name):
                self.assertIn("results", call(getattr(client, name), limit=1, page=1))

    def test_pulse_feeds_by_author(self) -> None:
        self.assertIn("results", call(client.my_pulses, limit=1, page=1))
        self.assertIn("results", call(client.user_pulses, "AlienVault", limit=1, page=1))

    def test_modified_since_filters(self) -> None:
        stamp = "2026-01-01T00:00:00+00:00"
        result = call(client.subscribed_pulses, limit=1, modified_since=stamp)
        self.assertIn("results", result)


class PulseWriteTests(unittest.TestCase):
    def test_pulse_lifecycle(self) -> None:
        created = call(client.create_pulse, PULSE_FIELDS)
        pulse_id = created["id"]
        try:
            self.assertEqual(created["name"], PULSE_FIELDS["name"])
            edited = call(client.edit_pulse, pulse_id, {"description": "edited by otxcli tests"})
            self.assertIsInstance(edited, dict)
        finally:
            deleted = call(client.delete_pulse, pulse_id)
        self.assertIn("removed", deleted["status"])

    def test_pulse_subscription(self) -> None:
        pulse_id = known_pulse_id()
        self.assertEqual(call(client.subscribe_to_pulse, pulse_id)["status"], "subscribed")
        result = call(client.unsubscribe_from_pulse, pulse_id)
        self.assertEqual(result["status"], "unsubscribed")


class UserTests(unittest.TestCase):
    def test_me(self) -> None:
        self.assertIn("username", call(client.me))

    def test_search_users(self) -> None:
        result = call(client.search_users, "alien", limit=1, page=1, sort="username")
        self.assertIn("results", result)

    def test_search_pulses_sorted(self) -> None:
        result = call(client.search_pulses, "zeus", limit=1, page=1, sort="modified")
        self.assertIn("results", result)

    def test_user_actions(self) -> None:
        self.assertEqual(call(client.subscribe_to_user, "AlienVault")["status"], "subscribed")
        self.assertEqual(call(client.unsubscribe_from_user, "AlienVault")["status"], "unsubscribed")
        self.assertEqual(call(client.follow_user, "AlienVault")["status"], "followed")
        self.assertEqual(call(client.unfollow_user, "AlienVault")["status"], "unfollowed")


class PathBuildingTests(unittest.TestCase):
    def test_separators_are_encoded(self) -> None:
        self.assertEqual(_path("pulses", "../users/me"), "/pulses/..%2Fusers%2Fme")

    def test_query_start_is_encoded(self) -> None:
        self.assertEqual(
            _path("indicators", "IPv4", "8.8.8.8", "general?limit=1"),
            "/indicators/IPv4/8.8.8.8/general%3Flimit%3D1",
        )

    def test_plain_segments_are_unchanged(self) -> None:
        self.assertEqual(_path("users", "me"), "/users/me")


class HostnameEncodingTests(unittest.TestCase):
    def test_ascii_hosts_are_untouched(self) -> None:
        """idna would reject the underscore and case-fold the second one."""
        for host in ("rghost.net", "_dmarc.example.com", "EXAMPLE.com", "xn--bcher-kva.de"):
            with self.subTest(host):
                self.assertEqual(_idna(host), host)

    def test_unicode_host_becomes_punycode(self) -> None:
        self.assertEqual(_idna("bücher.de"), "xn--bcher-kva.de")

    def test_homograph_maps_the_way_a_browser_would(self) -> None:
        """UTS46 folds these to ASCII; the stdlib codec invented a lookalike instead."""
        self.assertEqual(_idna("ᴳoogle.com"), "google.com")
        self.assertEqual(_idna("ₐpple.com"), "apple.com")

    def test_deviation_characters_keep_their_own_domain(self) -> None:
        """IDNA2003 turned these into strasse.de, a different registration."""
        self.assertEqual(_idna("straße.de"), "xn--strae-oqa.de")
        self.assertEqual(_idna("STRAẞE.de"), "xn--strae-oqa.de")

    def test_unrepresentable_host_is_passed_through(self) -> None:
        """Let the API name what it rejected rather than resolve something else."""
        oversized = "ü" * 64 + ".de"
        self.assertEqual(_idna(oversized), oversized)


class ResponseDecodingTests(unittest.TestCase):
    def test_empty_body_decodes_to_none(self) -> None:
        self.assertIsNone(_decode(204, "   "))

    def test_json_body_decodes(self) -> None:
        self.assertEqual(_decode(200, '{"a": 1}'), {"a": 1})

    def test_non_json_body_raises_otx_error(self) -> None:
        with self.assertRaises(OTXError) as raised:
            _decode(200, "<html>not json</html>")
        self.assertEqual(raised.exception.status, 200)
        self.assertIn("malformed JSON", raised.exception.detail)


class ErrorTests(unittest.TestCase):
    def test_invalid_api_key(self) -> None:
        bad = OTXClient(BAD_KEY, timeout=TIMEOUT)
        with self.assertRaises(OTXError) as raised:
            call(bad.me)
        self.assertEqual(raised.exception.status, 403)
        self.assertIsInstance(raised.exception.detail, str)

    def test_error_survives_reconstruction(self) -> None:
        """multiprocessing rebuilds exceptions from args; that must not raise TypeError."""
        restored = copy.copy(OTXError(429, "rate limited"))
        self.assertEqual(restored.status, 429)
        self.assertEqual(restored.detail, "rate limited")
        self.assertEqual(str(restored), "HTTP 429: rate limited")

    def test_indicator_cannot_escape_its_path_segment(self) -> None:
        with self.assertRaises(OTXError) as raised:
            call(client.pulse, "../users/me")
        self.assertGreaterEqual(raised.exception.status, 400)

    def test_section_cannot_inject_a_query_string(self) -> None:
        with self.assertRaises(OTXError) as raised:
            call(client.ipv4, "8.8.8.8", section="general?limit=1")
        self.assertGreaterEqual(raised.exception.status, 400)


class CommandTableTests(unittest.TestCase):
    """COMMANDS restates each client signature by hand, because which parameter becomes a
    flag, what it is called on the command line and how it is described are CLI decisions
    that cannot be read off the client. These checks keep the two copies from drifting."""

    def test_every_command_binds_to_its_client_method(self) -> None:
        parser = build_parser()
        with tempfile.TemporaryDirectory() as workdir:
            sample = Path(workdir) / "sample.bin"
            sample.write_bytes(FILE_CONTENT)
            for name, _, args in COMMANDS:
                with self.subTest(name):
                    argv = [name]
                    for arg_name, options in args:
                        if options.get("type") is json_object:
                            value = "{}"
                        elif name == "submit-file":
                            value = str(sample)
                        else:
                            value = "x"
                        if not arg_name.startswith("--"):
                            argv.append(value)
                        elif options.get("required"):
                            argv += [arg_name, value]
                    namespace = parser.parse_args(argv)
                    method = getattr(OTXClient, name.replace("-", "_"))
                    inspect.signature(method).bind(client, **_method_kwargs(namespace))

    def test_every_client_endpoint_is_reachable_from_the_cli(self) -> None:
        exposed = {name.replace("-", "_") for name, _, _ in COMMANDS}
        public = {n for n, v in vars(OTXClient).items() if callable(v) and not n.startswith("_")}
        self.assertEqual(public, exposed)


class CliTests(unittest.TestCase):
    def test_me_command(self) -> None:
        output = run_cli_ok("--api-key", API_KEY, "me")
        self.assertIn("username", json.loads(output))

    def test_indicator_command(self) -> None:
        output = run_cli_ok("ipv4", "8.8.8.8", "--section", "general")
        self.assertEqual(json.loads(output)["indicator"], "8.8.8.8")

    def test_submit_file_command(self) -> None:
        with tempfile.TemporaryDirectory() as workdir:
            sample = Path(workdir) / "otxcli_test.txt"
            sample.write_bytes(FILE_CONTENT)
            output = run_cli_ok("submit-file", str(sample))
        self.assertEqual(json.loads(output)["sha256"], FILE_SHA256)

    def test_failures_exit_with_a_message(self) -> None:
        """Every way a command can fail: exit 1, say why on stderr, never traceback."""
        for label, argv, expected in CLI_FAILURES:
            with self.subTest(label):
                run_cli_expecting_failure(expected, *argv)

    def test_api_key_env_is_read_at_invocation_time(self) -> None:
        """The environment must be consulted when main() runs, not when the module loads."""
        os.environ["OTX_API_KEY"] = BAD_KEY
        try:
            run_cli_expecting_failure("HTTP 403", "--timeout", str(TIMEOUT), "me")
        finally:
            os.environ["OTX_API_KEY"] = API_KEY

    def test_json_argument_must_be_an_object(self) -> None:
        self.assertEqual(json_object('{"a": 1}'), {"a": 1})
        with self.assertRaises(argparse.ArgumentTypeError):
            json_object("[1, 2]")

    def test_tlp_is_required_for_tlp_updates(self) -> None:
        for command in ("update-submitted-files-tlp", "update-submitted-urls-tlp"):
            with self.subTest(command=command), redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    main([command, "value"])
                self.assertEqual(raised.exception.code, 2)

    @staticmethod
    def _run_with_closed_stdout() -> tuple[int, str, bool]:
        """Run a command whose stdout is a pipe nobody is reading.

        Also reports whether main() left sys.stdout bound to the stream it was given: the
        broken pipe must not leak into later calls in the same process.
        """
        read_fd, write_fd = os.pipe()
        os.close(read_fd)
        stream = os.fdopen(write_fd, "w")
        original, err = sys.stdout, io.StringIO()
        try:
            sys.stdout = stream
            with redirect_stderr(err):
                code = main(["--api-key", API_KEY, "--timeout", str(TIMEOUT), "indicator-types"])
            kept_stdout = sys.stdout is stream
        finally:
            sys.stdout = original
            try:
                stream.close()
            except OSError:
                # POSIX reports the broken pipe as BrokenPipeError, Windows as EINVAL.
                pass
        return code, err.getvalue(), kept_stdout

    def test_closed_stdout_exits_without_traceback(self) -> None:
        err = ""
        for attempt in range(ATTEMPTS):
            code, err, kept_stdout = self._run_with_closed_stdout()
            if code == 1 and err == "":
                self.assertTrue(kept_stdout, "main() rebound sys.stdout for the whole process")
                return
            backoff(attempt)
        raise AssertionError(f"broken pipe was not handled cleanly: {err}")
