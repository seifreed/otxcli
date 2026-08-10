"""Client for every endpoint of the AlienVault OTX v1 API.

Reference: https://otx.alienvault.com/assets/static/external_api.html
"""

from __future__ import annotations

import json
import secrets
from http.client import HTTPSConnection
from typing import Any
from urllib.parse import quote, urlencode

import idna

DEFAULT_SERVER = "otx.alienvault.com"
DEFAULT_TIMEOUT = 120.0
DEFAULT_SECTION = "general"
API_ROOT = "/api/v1"


class OTXError(Exception):
    """Raised when an OTX API call fails or returns an unusable response."""

    def __init__(self, status: int, detail: str) -> None:
        super().__init__(status, detail)
        self.status = status
        self.detail = detail

    def __str__(self) -> str:
        return f"HTTP {self.status}: {self.detail}"


def _path(*segments: str) -> str:
    """Build an API path, percent-encoding each segment so it cannot span the next one."""
    return "".join("/" + quote(segment, safe="") for segment in segments)


def _idna(host: str) -> str:
    """Return the punycode form of a hostname, since OTX only resolves ASCII hosts.

    UTS46 mapping is what browsers and resolvers apply, so "ᴳoogle.com" reaches google.com
    rather than a lookalike nobody serves. An ASCII host is returned untouched: idna would
    reject the underscore in "_dmarc.example.com" and case-fold "EXAMPLE.com". A host it
    cannot represent is passed through, so the API objects instead of us resolving another
    domain.
    """
    if host.isascii():
        return host
    try:
        return idna.encode(host, uts46=True).decode("ascii")
    except idna.IDNAError:
        return host


def _decode(status: int, payload: str) -> Any:
    """Parse a successful response body, tolerating the empty bodies some endpoints return."""
    if not payload.strip():
        return None
    try:
        return json.loads(payload)
    except ValueError as error:
        raise OTXError(status, f"malformed JSON response: {error}") from error


class OTXClient:
    """Synchronous client for the OTX v1 API using only the standard library."""

    def __init__(
        self, api_key: str, server: str = DEFAULT_SERVER, timeout: float = DEFAULT_TIMEOUT
    ) -> None:
        self.api_key = api_key
        self.server = server
        self.timeout = timeout

    @staticmethod
    def _target(path: str, params: dict[str, Any] | None) -> str:
        target = API_ROOT + path
        query = {key: value for key, value in (params or {}).items() if value is not None}
        if query:
            target += "?" + urlencode(query)
        return target

    def _request(
        self,
        method: str,
        path: str,
        params: dict[str, Any] | None = None,
        body: bytes | None = None,
        content_type: str = "application/json",
    ) -> Any:
        target = self._target(path, params)
        headers = {"X-OTX-API-KEY": self.api_key, "Accept": "application/json"}
        if body is not None:
            headers["Content-Type"] = content_type
        connection = HTTPSConnection(self.server, timeout=self.timeout)
        try:
            connection.request(method, target, body=body, headers=headers)
            response = connection.getresponse()
            status = response.status
            payload = response.read().decode("utf-8", errors="replace")
        finally:
            connection.close()
        if status >= 300:
            raise OTXError(status, payload)
        return _decode(status, payload)

    def _get(self, path: str, **params: Any) -> Any:
        return self._request("GET", path, params=params)

    def _send_json(self, method: str, path: str, payload: dict[str, Any]) -> Any:
        return self._request(method, path, body=json.dumps(payload).encode("utf-8"))

    # Indicators

    def _indicator(self, kind: str, value: str, section: str) -> Any:
        return self._get(_path("indicators", kind, value, section))

    def ipv4(self, ip: str, section: str = DEFAULT_SECTION) -> Any:
        """Sections: general, reputation, geo, malware, url_list, passive_dns, http_scans."""
        return self._indicator("IPv4", ip, section)

    def ipv6(self, ip: str, section: str = DEFAULT_SECTION) -> Any:
        """Sections: general, reputation, geo, malware, url_list, passive_dns."""
        return self._indicator("IPv6", ip, section)

    def domain(self, domain: str, section: str = DEFAULT_SECTION) -> Any:
        """Sections: general, geo, malware, url_list, passive_dns, whois, http_scans."""
        return self._indicator("domain", _idna(domain), section)

    def hostname(self, hostname: str, section: str = DEFAULT_SECTION) -> Any:
        """Sections: general, geo, malware, url_list, passive_dns, http_scans."""
        return self._indicator("hostname", _idna(hostname), section)

    def file(self, file_hash: str, section: str = DEFAULT_SECTION) -> Any:
        """Sections: general, analysis."""
        return self._indicator("file", file_hash, section)

    def url(self, url: str, section: str = DEFAULT_SECTION) -> Any:
        """Sections: general, url_list."""
        return self._indicator("url", url, section)

    def cve(self, cve: str, section: str = DEFAULT_SECTION) -> Any:
        """Sections: general."""
        return self._indicator("cve", cve, section)

    def nids(self, nids: str, section: str = DEFAULT_SECTION) -> Any:
        """Sections: general."""
        return self._indicator("nids", nids, section)

    def correlation_rule(self, rule_id: str, section: str = DEFAULT_SECTION) -> Any:
        """Sections: general."""
        return self._indicator("correlation-rule", rule_id, section)

    def submit_file(self, filename: str, data: bytes) -> Any:
        boundary = secrets.token_hex(16)
        safe_name = filename.replace("\r", "").replace("\n", "").replace('"', "%22")
        head = (
            f'--{boundary}\r\nContent-Disposition: form-data; name="file"; '
            f'filename="{safe_name}"\r\nContent-Type: application/octet-stream\r\n\r\n'
        ).encode()
        body = head + data + f"\r\n--{boundary}--\r\n".encode()
        return self._request(
            "POST",
            "/indicators/submit_file",
            body=body,
            content_type=f"multipart/form-data; boundary={boundary}",
        )

    def submitted_files(
        self, limit: int | None = None, page: int | None = None, sort: str | None = None
    ) -> Any:
        """Sort by one of: add_date, sha256, complete_date."""
        return self._get("/indicators/submitted_files", limit=limit, page=page, sort=sort)

    def _post_with_tlp(self, path: str, field: str, value: Any, tlp: str | None) -> Any:
        payload: dict[str, Any] = {field: value}
        if tlp is not None:
            payload["tlp"] = tlp
        return self._send_json("POST", path, payload)

    def update_submitted_files_tlp(self, hashes: list[str], tlp: str) -> Any:
        """TLP is one of: white, green, amber, red."""
        return self._post_with_tlp("/indicators/update_submitted_files_tlp", "hashes", hashes, tlp)

    def submit_url(self, url: str, tlp: str | None = None) -> Any:
        return self._post_with_tlp("/indicators/submit_url", "url", url, tlp)

    def submit_urls(self, urls: list[str], tlp: str | None = None) -> Any:
        return self._post_with_tlp("/indicators/submit_urls", "urls", urls, tlp)

    def submitted_urls(
        self, limit: int | None = None, page: int | None = None, sort: str | None = None
    ) -> Any:
        """Sort by one of: add_date, url, complete_date."""
        return self._get("/indicators/submitted_urls", limit=limit, page=page, sort=sort)

    def update_submitted_urls_tlp(self, urls: list[str], tlp: str) -> Any:
        """TLP is one of: white, green, amber, red."""
        return self._post_with_tlp("/indicators/update_submitted_urls_tlp", "urls", urls, tlp)

    # Pulses

    def _pulse_endpoint(self, pulse_id: str, suffix: str, **params: Any) -> Any:
        return self._get(_path("pulses", pulse_id, suffix), **params)

    def pulse(self, pulse_id: str) -> Any:
        return self._get(_path("pulses", pulse_id))

    def edit_pulse(self, pulse_id: str, changes: dict[str, Any]) -> Any:
        return self._send_json("PATCH", _path("pulses", pulse_id), changes)

    def pulse_indicators(
        self, pulse_id: str, limit: int | None = None, page: int | None = None
    ) -> Any:
        return self._pulse_endpoint(pulse_id, "indicators", limit=limit, page=page)

    def pulse_related(
        self, pulse_id: str, limit: int | None = None, page: int | None = None
    ) -> Any:
        return self._pulse_endpoint(pulse_id, "related", limit=limit, page=page)

    def related_pulses(
        self,
        pulse_id: str | None = None,
        malware_family: str | None = None,
        adversary: str | None = None,
        limit: int | None = None,
        page: int | None = None,
    ) -> Any:
        """Use exactly one of pulse_id, malware_family or adversary."""
        return self._get(
            "/pulses/related",
            pulse_id=pulse_id,
            malware_family=malware_family,
            adversary=adversary,
            limit=limit,
            page=page,
        )

    def subscribed_pulses(
        self,
        limit: int | None = None,
        page: int | None = None,
        modified_since: str | None = None,
    ) -> Any:
        return self._get(
            "/pulses/subscribed", limit=limit, page=page, modified_since=modified_since
        )

    def subscribed_pulse_ids(self, limit: int | None = None, page: int | None = None) -> Any:
        return self._get("/pulses/subscribed_pulse_ids", limit=limit, page=page)

    def activity(
        self,
        limit: int | None = None,
        page: int | None = None,
        modified_since: str | None = None,
    ) -> Any:
        return self._get("/pulses/activity", limit=limit, page=page, modified_since=modified_since)

    def create_pulse(self, fields: dict[str, Any]) -> Any:
        """Required fields: name, public. See the API docs for the full schema."""
        return self._send_json("POST", "/pulses/create", fields)

    def delete_pulse(self, pulse_id: str) -> Any:
        return self._pulse_endpoint(pulse_id, "delete")

    def subscribe_to_pulse(self, pulse_id: str) -> Any:
        return self._pulse_endpoint(pulse_id, "subscribe")

    def unsubscribe_from_pulse(self, pulse_id: str) -> Any:
        return self._pulse_endpoint(pulse_id, "unsubscribe")

    def indicator_types(self) -> Any:
        return self._get("/pulses/indicators/types")

    def validate_indicator(self, indicator_type: str, indicator: str) -> Any:
        return self._send_json(
            "POST", "/pulses/indicators/validate", {"type": indicator_type, "indicator": indicator}
        )

    def events(
        self,
        limit: int | None = None,
        page: int | None = None,
        modified_since: str | None = None,
    ) -> Any:
        return self._get("/pulses/events", limit=limit, page=page, modified_since=modified_since)

    def user_pulses(
        self,
        username: str,
        limit: int | None = None,
        page: int | None = None,
        since: str | None = None,
    ) -> Any:
        return self._get(_path("pulses", "user", username), limit=limit, page=page, since=since)

    def my_pulses(
        self, limit: int | None = None, page: int | None = None, since: str | None = None
    ) -> Any:
        return self._get("/pulses/my", limit=limit, page=page, since=since)

    # Search

    def search_pulses(
        self,
        q: str,
        limit: int | None = None,
        page: int | None = None,
        sort: str | None = None,
    ) -> Any:
        """Sort by one of: created, modified, name, description, reference, pulse_count,
        indicator_count, member_count."""
        return self._get("/search/pulses", q=q, limit=limit, page=page, sort=sort)

    def search_users(
        self,
        q: str,
        limit: int | None = None,
        page: int | None = None,
        sort: str | None = None,
    ) -> Any:
        """Sort by one of: username, user_id, pulse_count."""
        return self._get("/search/users", q=q, limit=limit, page=page, sort=sort)

    # Users

    def me(self) -> Any:
        return self._get("/users/me")

    def _user_action(self, username: str, action: str) -> Any:
        return self._get(_path("users", username, action))

    def subscribe_to_user(self, username: str) -> Any:
        return self._user_action(username, "subscribe")

    def unsubscribe_from_user(self, username: str) -> Any:
        return self._user_action(username, "unsubscribe")

    def follow_user(self, username: str) -> Any:
        return self._user_action(username, "follow")

    def unfollow_user(self, username: str) -> Any:
        return self._user_action(username, "unfollow")
