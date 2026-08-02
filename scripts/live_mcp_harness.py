#!/usr/bin/env python3
"""Shared, standard-library-only helpers for opt-in loopback Burp live diagnostics."""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
import pathlib
import socket
import stat
import struct
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable

SUPPORTED_PROTOCOLS = ("2025-03-26", "2025-06-18", "2025-11-25")
WEBSOCKET_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
MAX_MCP_RESPONSE_BYTES = 16 * 1024 * 1024
HISTORY_PERFORMANCE_BUCKET_COUNT = 11
HISTORY_PERFORMANCE_METRICS = (
    "INDEX_PROXY_ACQUISITION",
    "INDEX_PROXY_PROCESSING",
    "INDEX_SITE_MAP_ACQUISITION",
    "INDEX_SITE_MAP_PROCESSING",
    "INDEX_ORGANIZER_ACQUISITION",
    "INDEX_ORGANIZER_PROCESSING",
    "HTTP_SEARCH_PROXY_ACQUISITION",
    "HTTP_SEARCH_SITE_MAP_ACQUISITION",
    "HTTP_SEARCH_ORGANIZER_ACQUISITION",
    "HTTP_SEARCH_PROCESSING",
    "WEBSOCKET_SEARCH_ACQUISITION",
    "WEBSOCKET_SEARCH_PROCESSING",
    "RELATED_CORRELATION_MONTOYA_ACQUISITION",
    "RELATED_CORRELATION_EXTENSION_PROCESSING",
    "SCANNER_DELTA_MONTOYA_ACQUISITION",
    "SCANNER_DELTA_EXTENSION_PROCESSING",
)
_HISTORY_PERFORMANCE_COUNTER_FIELDS = ("attempts", "completed", "failed", "cancelled", "totalNanos")
_HISTORY_PERFORMANCE_METRIC_FIELDS = frozenset(
    {"metric", "active", "latencyBuckets", "maxNanos", *_HISTORY_PERFORMANCE_COUNTER_FIELDS}
)
_MAX_SIGNED_LONG = (1 << 63) - 1


class HarnessError(RuntimeError):
    """A bounded error safe to put in local diagnostic output."""


def bounded_system_failure(error: BaseException) -> str:
    """Classify dependency failures without serializing paths, endpoints, or payloads."""
    if isinstance(error, (TimeoutError, subprocess.TimeoutExpired)):
        return "live diagnostic operation timed out"
    if isinstance(error, subprocess.SubprocessError):
        return "live diagnostic subprocess failed"
    return "live diagnostic system operation failed"


class _RejectRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


def validate_loopback_endpoint(value: str) -> str:
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "::1", "localhost"}:
        raise HarnessError("MCP endpoint must use HTTP on a loopback host")
    if parsed.path != "/mcp" or parsed.query or parsed.fragment or parsed.username or parsed.password:
        raise HarnessError("MCP endpoint must contain only the /mcp path")
    if parsed.port is None or parsed.port not in range(1, 65_536):
        raise HarnessError("MCP endpoint must include a valid port")
    return value


def unauthenticated_http_status(endpoint: str, timeout: float = 5) -> int:
    """Return one bounded loopback status without following redirects or retaining a response body."""
    validate_loopback_endpoint(endpoint)
    if timeout <= 0 or timeout > 30:
        raise HarnessError("unauthenticated probe timeout is outside its safety bound")
    opener = urllib.request.build_opener(_RejectRedirects())
    request = urllib.request.Request(
        endpoint,
        headers={"Accept": "application/json, text/event-stream"},
        method="GET",
    )
    try:
        with opener.open(request, timeout=timeout) as response:
            response.read(4096)
            return response.status
    except urllib.error.HTTPError as error:
        try:
            try:
                error.read(4096)
            except OSError:
                pass
            return error.code
        finally:
            error.close()


def read_private_text_file(path: pathlib.Path, *, min_chars: int, max_chars: int) -> str:
    if min_chars < 1 or max_chars < min_chars or max_chars > 4096:
        raise HarnessError("private file character bound is invalid")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise HarnessError("private input must be a regular non-symlink file") from error
    with os.fdopen(descriptor, "rb") as source:
        metadata = os.fstat(source.fileno())
        if not stat.S_ISREG(metadata.st_mode):
            raise HarnessError("private input must be a regular non-symlink file")
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            raise HarnessError("private input permissions must not grant group or other access")
        content = source.read(max_chars * 4 + 2)
        if len(content) > max_chars * 4 + 1:
            raise HarnessError("private input exceeded its safety bound")
    try:
        value = content.decode("utf-8").strip()
    except UnicodeDecodeError as error:
        raise HarnessError("private input content is invalid") from error
    if not min_chars <= len(value) <= max_chars or any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise HarnessError("private input content is invalid")
    return value


def read_private_token(path: pathlib.Path) -> str:
    token = read_private_text_file(path, min_chars=43, max_chars=128)
    if not all(character.isascii() and (character.isalnum() or character in "_-") for character in token):
        raise HarnessError("token file does not contain a valid local bearer value")
    return token


def read_private_json_file(path: pathlib.Path, *, max_bytes: int = 64 * 1024) -> dict[str, Any]:
    """Read one private, single-link JSON object without logging or retaining its path."""
    if max_bytes < 2 or max_bytes > 1024 * 1024:
        raise HarnessError("private JSON file bound is invalid")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise HarnessError("private JSON input must be a regular non-symlink file") from error
    with os.fdopen(descriptor, "rb") as source:
        metadata = os.fstat(source.fileno())
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) & 0o077
            or metadata.st_size > max_bytes
        ):
            raise HarnessError("private JSON input must be a single-link private bounded file")
        content = source.read(max_bytes + 1)
        if len(content) > max_bytes:
            raise HarnessError("private JSON input exceeded its safety bound")

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise HarnessError("private JSON input contained duplicate keys")
            value[key] = item
        return value

    try:
        decoded = json.loads(content.decode("utf-8"), object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise HarnessError("private JSON input was invalid") from error
    if not isinstance(decoded, dict):
        raise HarnessError("private JSON input must contain one object")
    pending: list[tuple[Any, int]] = [(decoded, 0)]
    tokens = 0
    while pending:
        value, depth = pending.pop()
        tokens += 1
        if tokens > 10_000 or depth > 32:
            raise HarnessError("private JSON input exceeded structural bounds")
        if isinstance(value, dict):
            if any(not isinstance(key, str) or len(key) > 128 for key in value):
                raise HarnessError("private JSON input contained an invalid key")
            pending.extend((item, depth + 1) for item in value.values())
        elif isinstance(value, list):
            pending.extend((item, depth + 1) for item in value)
        elif value is not None and not isinstance(value, (str, int, float, bool)):
            raise HarnessError("private JSON input contained an unsupported value")
    return decoded


def read_bounded_regular_file(path: pathlib.Path, max_bytes: int) -> bytes:
    if max_bytes < 1 or max_bytes > 512 * 1024 * 1024:
        raise HarnessError("file read bound is invalid")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise HarnessError("input must be a readable regular non-symlink file") from error
    with os.fdopen(descriptor, "rb") as source:
        metadata = os.fstat(source.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > max_bytes:
            raise HarnessError("input must be a bounded regular non-symlink file")
        content = source.read(max_bytes + 1)
        if len(content) > max_bytes:
            raise HarnessError("input exceeded its file read bound")
        return content


def sha256_file(path: pathlib.Path) -> str:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise HarnessError("hash input must be a readable regular non-symlink file") from error
    digest = hashlib.sha256()
    with os.fdopen(descriptor, "rb") as source:
        metadata = os.fstat(source.fileno())
        if not stat.S_ISREG(metadata.st_mode):
            raise HarnessError("hash input must be a readable regular non-symlink file")
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def current_rss_kib(pid: int | None) -> int | None:
    if pid is None:
        return None
    if pid <= 0:
        raise HarnessError("Burp PID must be positive")
    result = subprocess.run(
        ["ps", "-o", "rss=", "-p", str(pid)],
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )
    value = result.stdout.strip()
    if result.returncode != 0 or not value.isdigit():
        raise HarnessError("could not read Burp process RSS")
    return int(value)


def enforce_rss_limit(pid: int | None, max_rss_kib: int) -> int | None:
    rss = current_rss_kib(pid)
    if rss is not None and rss > max_rss_kib:
        raise HarnessError("Burp process RSS exceeded the configured safety limit")
    return rss


def bounded_rss_snapshot(pid: int | None, max_rss_kib: int) -> tuple[int | None, str | None]:
    """Observe final RSS without allowing a secondary dependency failure to suppress a report."""
    try:
        rss = current_rss_kib(pid)
    except HarnessError as error:
        return None, str(error)
    except (OSError, subprocess.SubprocessError) as error:
        return None, bounded_system_failure(error)
    if rss is not None and rss > max_rss_kib:
        return rss, "Burp process RSS exceeded the configured safety limit"
    return rss, None


class McpClient:
    def __init__(self, endpoint: str, token: str, protocol: str = "2025-11-25") -> None:
        self.endpoint = validate_loopback_endpoint(endpoint)
        if protocol not in SUPPORTED_PROTOCOLS:
            raise HarnessError("unsupported protocol selection")
        self.token = token
        self.protocol = protocol
        self.session_id: str | None = None
        self.next_id = 1
        self._opener = urllib.request.build_opener(_RejectRedirects())

    def request(
        self,
        body: dict[str, Any] | None = None,
        method: str = "POST",
        include_session: bool = True,
        timeout: float = 60,
    ) -> tuple[int, dict[str, str], Any]:
        headers = {
            "Accept": "application/json, text/event-stream",
            "Authorization": "Bearer " + self.token,
            "Mcp-Protocol-Version": self.protocol,
        }
        if include_session and self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
        data = None
        if body is not None:
            data = json.dumps(body, separators=(",", ":")).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(self.endpoint, data=data, headers=headers, method=method)
        try:
            with self._opener.open(request, timeout=timeout) as response:
                payload = response.read(MAX_MCP_RESPONSE_BYTES + 1)
                if len(payload) > MAX_MCP_RESPONSE_BYTES:
                    raise HarnessError("MCP response exceeded its safety bound")
                raw = payload.decode("utf-8", errors="replace")
                try:
                    parsed = json.loads(raw) if raw.strip() else None
                except json.JSONDecodeError:
                    parsed = None
                return response.status, dict(response.headers.items()), parsed
        except urllib.error.HTTPError as error:
            try:
                try:
                    payload = error.read(MAX_MCP_RESPONSE_BYTES + 1)
                except OSError:
                    payload = b""
                if len(payload) > MAX_MCP_RESPONSE_BYTES:
                    raise HarnessError("MCP error response exceeded its safety bound")
                raw = payload.decode("utf-8", errors="replace")
                try:
                    parsed = json.loads(raw) if raw.strip() else None
                except json.JSONDecodeError:
                    parsed = None
                return error.code, dict(error.headers.items()), parsed
            finally:
                error.close()

    def initialize(self) -> dict[str, Any]:
        body = {
            "jsonrpc": "2.0",
            "id": self.next_id,
            "method": "initialize",
            "params": {
                "protocolVersion": self.protocol,
                "capabilities": {},
                "clientInfo": {"name": "independent-live-diagnostics", "version": "1"},
            },
        }
        self.next_id += 1
        status, headers, response = self.request(body, include_session=False)
        if status != 200 or not isinstance(response, dict):
            raise HarnessError("MCP initialization failed")
        self.session_id = next(
            (value for key, value in headers.items() if key.lower() == "mcp-session-id"),
            None,
        )
        if not self.session_id:
            raise HarnessError("MCP initialization did not return a session")
        negotiated = ((response.get("result") or {}).get("protocolVersion"))
        if negotiated != self.protocol:
            raise HarnessError("MCP initialization negotiated an unexpected protocol")
        initialized_status, _, _ = self.request(
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            timeout=30,
        )
        if initialized_status not in {200, 202}:
            raise HarnessError("MCP initialized notification failed")
        return response

    def rpc(self, method: str, params: dict[str, Any] | None = None, timeout: float = 120) -> Any:
        body: dict[str, Any] = {"jsonrpc": "2.0", "id": self.next_id, "method": method}
        self.next_id += 1
        if params is not None:
            body["params"] = params
        status, _, response = self.request(body, timeout=timeout)
        if status != 200 or not isinstance(response, dict):
            raise HarnessError("MCP request failed")
        return response

    def close(self) -> int | None:
        if not self.session_id:
            return None
        try:
            status, _, _ = self.request(method="DELETE", body=None, timeout=30)
            return status
        finally:
            self.session_id = None


class InterruptibleMcpToolCall:
    """One bounded MCP tool POST whose socket can be closed after a diagnostics barrier."""

    def __init__(
        self,
        client: McpClient,
        name: str,
        arguments: dict[str, Any],
        *,
        request_id: int,
        timeout: float = 120,
        max_response_bytes: int = 4 * 1024 * 1024,
    ) -> None:
        if not client.session_id:
            raise HarnessError("interruptible call requires an initialized MCP session")
        if not name or len(name) > 128 or any(ord(character) < 33 or ord(character) > 126 for character in name):
            raise HarnessError("interruptible call tool name is invalid")
        if request_id < 1 or request_id > 2_147_483_647:
            raise HarnessError("interruptible call request ID is invalid")
        if timeout <= 0 or timeout > 300 or max_response_bytes not in range(1024, 16 * 1024 * 1024 + 1):
            raise HarnessError("interruptible call bound is invalid")
        body = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "method": "tools/call",
                "params": {"name": name, "arguments": arguments},
            },
            separators=(",", ":"),
        ).encode("utf-8")
        if len(body) > 1024 * 1024:
            raise HarnessError("interruptible call request exceeded its safety bound")
        self._endpoint = urllib.parse.urlsplit(client.endpoint)
        self._headers = {
            "Accept": "application/json, text/event-stream",
            "Authorization": "Bearer " + client.token,
            "Content-Type": "application/json",
            "Mcp-Protocol-Version": client.protocol,
            "Mcp-Session-Id": client.session_id,
        }
        self._body = body
        self._timeout = timeout
        self._max_response_bytes = max_response_bytes
        self._lock = threading.Lock()
        self._connection: http.client.HTTPConnection | None = None
        self._abort_requested = threading.Event()
        self.completed = threading.Event()
        self._summary: dict[str, Any] = {"state": "not_started"}
        self._thread = threading.Thread(target=self._run, name="InterruptibleMcpToolCall", daemon=True)

    def start(self) -> None:
        with self._lock:
            if self._summary["state"] != "not_started":
                raise HarnessError("interruptible call can only be started once")
            self._summary = {"state": "running"}
        self._thread.start()

    def _run(self) -> None:
        connection = http.client.HTTPConnection(
            self._endpoint.hostname,
            self._endpoint.port,
            timeout=self._timeout,
        )
        with self._lock:
            self._connection = connection
        try:
            connection.request("POST", self._endpoint.path, body=self._body, headers=self._headers)
            response = connection.getresponse()
            payload = response.read(self._max_response_bytes + 1)
            if len(payload) > self._max_response_bytes:
                raise HarnessError("interruptible call response exceeded its safety bound")
            try:
                parsed = json.loads(payload.decode("utf-8")) if payload.strip() else None
            except (UnicodeDecodeError, json.JSONDecodeError):
                parsed = None
            # A complete response is never reclassified as cancellation merely because abort raced with it.
            summary = {
                "state": "completed",
                "httpStatus": response.status,
                "jsonRpcResponse": isinstance(parsed, dict),
            }
        except (HarnessError, OSError, TimeoutError, http.client.HTTPException):
            summary = {
                "state": "aborted" if self._abort_requested.is_set() else "failed",
                "httpStatus": None,
                "jsonRpcResponse": False,
            }
        finally:
            connection.close()
            with self._lock:
                self._connection = None
                self._summary = summary
            self.completed.set()

    def abort(self) -> bool:
        with self._lock:
            connection = self._connection
            sock = None if connection is None else connection.sock
        if sock is None:
            return False
        self._abort_requested.set()
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            sock.close()
        except OSError:
            pass
        return True

    def join(self, timeout: float = 10) -> None:
        if timeout <= 0 or timeout > 120:
            raise HarnessError("interruptible call join timeout is outside its safety bound")
        self._thread.join(timeout)
        if self._thread.is_alive():
            raise HarnessError("interruptible call did not stop within its safety bound")

    def summary(self) -> dict[str, Any]:
        with self._lock:
            return dict(self._summary)


def structured_content(response: Any) -> dict[str, Any]:
    try:
        value = response["result"]["structuredContent"]
    except (KeyError, TypeError):
        raise HarnessError("MCP tool response did not contain structured content")
    if not isinstance(value, dict):
        raise HarnessError("MCP structured content was not an object")
    return value


def read_project_id(client: McpClient) -> str:
    response = client.rpc("resources/read", {"uri": "burp://project/summary"})
    try:
        text = response["result"]["contents"][0]["text"]
        value = json.loads(text)
        project_id = value["projectId"]
    except (KeyError, IndexError, TypeError, json.JSONDecodeError):
        raise HarnessError("project summary did not contain a valid project binding")
    if not isinstance(project_id, str) or not 1 <= len(project_id) <= 256 or any(ord(c) < 32 for c in project_id):
        raise HarnessError("project summary returned an invalid project binding")
    return project_id


def read_bounded_diagnostics(client: McpClient) -> tuple[dict[str, Any], str]:
    """Read the fixed-cardinality diagnostics resource and return its raw text for private leak checks."""
    response = client.rpc("resources/read", {"uri": "burp://diagnostics"})
    try:
        text = response["result"]["contents"][0]["text"]
        value = json.loads(text)["diagnostics"]
    except (KeyError, IndexError, TypeError, json.JSONDecodeError):
        raise HarnessError("diagnostics resource did not contain its bounded snapshot")
    if not isinstance(text, str) or not isinstance(value, dict):
        raise HarnessError("diagnostics resource did not contain its bounded snapshot")
    allowed = {
        "activeHttpCalls",
        "peakHttpCalls",
        "pendingSessions",
        "activeSessions",
        "activeEventStreams",
        "openedEventStreams",
        "closedEventStreams",
        "reopenedEventStreams",
        "initializedSessions",
        "sessionDeleteRequests",
        "pressureEvictions",
        "idleEvictions",
        "overloadRejections",
        "sessionCapacityRejections",
        "sessionsWithApprovals",
        "sessionApprovalGrants",
        "loadedArtifactSha256",
        "webSocketSearchActive",
        "webSocketSearchCompleted",
        "webSocketSearchCancelled",
    }
    return {key: value.get(key) for key in sorted(allowed)}, text


def parse_history_performance_snapshot(diagnostics_text: str) -> dict[str, dict[str, Any]]:
    """Parse the fixed, value-free history metrics exposed by the existing diagnostics resource."""
    if not isinstance(diagnostics_text, str) or len(diagnostics_text.encode("utf-8")) > 2 * 1024 * 1024:
        raise HarnessError("diagnostics history snapshot was not bounded text")
    try:
        diagnostics = json.loads(diagnostics_text)["diagnostics"]
        history = diagnostics["historyPerformance"]
        metrics = history["metrics"]
    except (KeyError, TypeError, json.JSONDecodeError):
        raise HarnessError("diagnostics history snapshot was malformed")
    if not isinstance(history, dict) or set(history) != {"metrics"} or not isinstance(metrics, list):
        raise HarnessError("diagnostics history snapshot was malformed")
    if len(metrics) != len(HISTORY_PERFORMANCE_METRICS):
        raise HarnessError("diagnostics history metric cardinality changed")

    parsed: dict[str, dict[str, Any]] = {}
    for expected_name, value in zip(HISTORY_PERFORMANCE_METRICS, metrics, strict=True):
        if not isinstance(value, dict) or set(value) != _HISTORY_PERFORMANCE_METRIC_FIELDS:
            raise HarnessError("diagnostics history metric fields changed")
        name = value.get("metric")
        if name != expected_name or name in parsed:
            raise HarnessError("diagnostics history metric identity or order changed")
        active = value.get("active")
        if isinstance(active, bool) or not isinstance(active, int) or active not in range(0, 65):
            raise HarnessError("diagnostics history active count was invalid")
        normalized: dict[str, Any] = {"active": active}
        for field in _HISTORY_PERFORMANCE_COUNTER_FIELDS + ("maxNanos",):
            counter = value.get(field)
            if (
                isinstance(counter, bool)
                or not isinstance(counter, int)
                or counter < 0
                or counter >= _MAX_SIGNED_LONG
            ):
                raise HarnessError("diagnostics history counter was invalid or saturated")
            normalized[field] = counter
        buckets = value.get("latencyBuckets")
        if (
            not isinstance(buckets, list)
            or len(buckets) != HISTORY_PERFORMANCE_BUCKET_COUNT
            or any(isinstance(item, bool) or not isinstance(item, int) or item < 0 for item in buckets)
            or any(item >= _MAX_SIGNED_LONG for item in buckets)
        ):
            raise HarnessError("diagnostics history buckets were invalid or saturated")
        if normalized["attempts"] != normalized["completed"] + normalized["failed"] + normalized["cancelled"]:
            raise HarnessError("diagnostics history outcomes were inconsistent")
        if sum(buckets) != normalized["attempts"]:
            raise HarnessError("diagnostics history buckets were inconsistent")
        if normalized["maxNanos"] > normalized["totalNanos"]:
            raise HarnessError("diagnostics history elapsed totals were inconsistent")
        if normalized["attempts"] == 0 and (normalized["totalNanos"] != 0 or normalized["maxNanos"] != 0):
            raise HarnessError("unused diagnostics history metric retained elapsed time")
        normalized["latencyBuckets"] = list(buckets)
        parsed[name] = normalized
    return parsed


def diff_history_performance_snapshots(
    before: dict[str, dict[str, Any]],
    after: dict[str, dict[str, Any]],
    expected_changed_metrics: frozenset[str],
) -> dict[str, dict[str, Any]]:
    """Difference quiet serial snapshots and reject contamination, regression, or saturation."""
    if set(before) != set(HISTORY_PERFORMANCE_METRICS) or set(after) != set(HISTORY_PERFORMANCE_METRICS):
        raise HarnessError("diagnostics history snapshots did not contain the fixed metric set")
    if not expected_changed_metrics or not expected_changed_metrics.issubset(HISTORY_PERFORMANCE_METRICS):
        raise HarnessError("expected diagnostics history metrics were invalid")
    differences: dict[str, dict[str, Any]] = {}
    for name in HISTORY_PERFORMANCE_METRICS:
        earlier = before[name]
        later = after[name]
        if earlier.get("active") != 0 or later.get("active") != 0:
            raise HarnessError("diagnostics history measurement boundary was active")
        for field in _HISTORY_PERFORMANCE_COUNTER_FIELDS + ("maxNanos",):
            if later.get(field, -1) < earlier.get(field, 0):
                raise HarnessError("diagnostics history counter regressed")
        earlier_buckets = earlier.get("latencyBuckets")
        later_buckets = later.get("latencyBuckets")
        if not isinstance(earlier_buckets, list) or not isinstance(later_buckets, list):
            raise HarnessError("diagnostics history buckets were malformed")
        if any(later_value < earlier_value for earlier_value, later_value in zip(earlier_buckets, later_buckets, strict=True)):
            raise HarnessError("diagnostics history bucket regressed")
        persistent_fields = _HISTORY_PERFORMANCE_COUNTER_FIELDS + ("maxNanos", "latencyBuckets")
        if name not in expected_changed_metrics:
            if any(earlier.get(field) != later.get(field) for field in persistent_fields):
                raise HarnessError("unrelated diagnostics history metric changed during the quiet measurement")
            continue
        delta = {
            field: later[field] - earlier[field]
            for field in _HISTORY_PERFORMANCE_COUNTER_FIELDS
        }
        delta_buckets = [
            later_value - earlier_value
            for earlier_value, later_value in zip(earlier_buckets, later_buckets, strict=True)
        ]
        if delta["attempts"] <= 0:
            raise HarnessError("target diagnostics history metric did not record the measurement")
        if delta["attempts"] != delta["completed"] + delta["failed"] + delta["cancelled"]:
            raise HarnessError("target diagnostics history outcome delta was inconsistent")
        if sum(delta_buckets) != delta["attempts"]:
            raise HarnessError("target diagnostics history bucket delta was inconsistent")
        differences[name] = {
            **delta,
            "latencyBuckets": delta_buckets,
            "activeBefore": earlier["active"],
            "activeAfter": later["active"],
            "maxNanosBefore": earlier["maxNanos"],
            "maxNanosAfter": later["maxNanos"],
        }
    return differences


def wait_for_active_http_call_barrier(
    read_snapshot: Callable[[], dict[str, Any]],
    operation_completed: threading.Event,
    *,
    minimum_active_calls: int = 2,
    timeout: float = 10,
    poll_interval: float = 0.01,
) -> dict[str, Any]:
    """Observe a real in-flight target call; the diagnostics observer itself accounts for one call."""
    if minimum_active_calls not in range(2, 65):
        raise HarnessError("active-call barrier threshold is outside its safety bound")
    if timeout <= 0 or timeout > 120 or poll_interval < 0.001 or poll_interval > 1:
        raise HarnessError("active-call barrier timing is outside its safety bound")
    started = time.monotonic()
    polls = 0
    maximum_observed = 0
    while time.monotonic() - started < timeout:
        if operation_completed.is_set():
            raise HarnessError("target operation completed before the active-call barrier")
        snapshot = read_snapshot()
        polls += 1
        active = snapshot.get("activeHttpCalls")
        if isinstance(active, bool) or not isinstance(active, int) or active < 1 or active > 64:
            raise HarnessError("diagnostics returned an invalid active HTTP call count")
        maximum_observed = max(maximum_observed, active)
        if active >= minimum_active_calls:
            return {
                "observed": True,
                "minimumActiveCalls": minimum_active_calls,
                "maximumObservedActiveCalls": maximum_observed,
                "polls": polls,
                "clientWallSeconds": round(time.monotonic() - started, 6),
                "targetCompletedBeforeBarrier": False,
            }
        time.sleep(min(poll_interval, max(0.0, timeout - (time.monotonic() - started))))
    raise HarnessError("active-call barrier timed out before observing the target operation")


def wait_for_websocket_search_processing_barrier(
    read_snapshot: Callable[[], dict[str, Any]],
    operation_completed: threading.Event,
    *,
    timeout: float = 10,
    poll_interval: float = 0.01,
) -> dict[str, Any]:
    """Observe the target inside measured WebSocket processing, not merely admitted at HTTP."""
    if timeout <= 0 or timeout > 120 or poll_interval < 0.001 or poll_interval > 1:
        raise HarnessError("WebSocket processing barrier timing is outside its safety bound")
    started = time.monotonic()
    polls = 0
    maximum_http_calls = 0
    maximum_processing = 0
    while time.monotonic() - started < timeout:
        if operation_completed.is_set():
            raise HarnessError("target operation completed before the WebSocket processing barrier")
        snapshot = read_snapshot()
        polls += 1
        active_http = snapshot.get("activeHttpCalls")
        active_processing = snapshot.get("webSocketSearchActive")
        if isinstance(active_http, bool) or not isinstance(active_http, int) or active_http < 1 or active_http > 64:
            raise HarnessError("diagnostics returned an invalid active HTTP call count")
        if (
            isinstance(active_processing, bool)
            or not isinstance(active_processing, int)
            or active_processing < 0
            or active_processing > 64
        ):
            raise HarnessError("diagnostics returned an invalid active WebSocket search count")
        maximum_http_calls = max(maximum_http_calls, active_http)
        maximum_processing = max(maximum_processing, active_processing)
        if active_http >= 2 and active_processing >= 1:
            return {
                "observed": True,
                "minimumActiveHttpCalls": 2,
                "maximumObservedActiveHttpCalls": maximum_http_calls,
                "minimumActiveWebSocketSearches": 1,
                "maximumObservedActiveWebSocketSearches": maximum_processing,
                "polls": polls,
                "clientWallSeconds": round(time.monotonic() - started, 6),
                "targetCompletedBeforeBarrier": False,
            }
        time.sleep(min(poll_interval, max(0.0, timeout - (time.monotonic() - started))))
    raise HarnessError("WebSocket processing barrier timed out before observing the target operation")


def classify_websocket_search_outcome_delta(
    before: dict[str, Any],
    after: dict[str, Any],
) -> dict[str, Any]:
    def counter(snapshot: dict[str, Any], key: str) -> int:
        value = snapshot.get(key)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0 or value > (1 << 63) - 1:
            raise HarnessError("diagnostics returned an invalid operation outcome counter")
        return value

    completed_before = counter(before, "webSocketSearchCompleted")
    cancelled_before = counter(before, "webSocketSearchCancelled")
    completed_after = counter(after, "webSocketSearchCompleted")
    cancelled_after = counter(after, "webSocketSearchCancelled")
    if completed_before == (1 << 63) - 1 or cancelled_before == (1 << 63) - 1:
        raise HarnessError("WebSocket outcome counter is saturated")
    completed_delta = completed_after - completed_before
    cancelled_delta = cancelled_after - cancelled_before
    if (completed_delta, cancelled_delta) == (0, 1):
        outcome = "cancelled"
    elif (completed_delta, cancelled_delta) == (1, 0):
        outcome = "completed"
    else:
        raise HarnessError("server outcome counters did not record exactly one bounded WebSocket search")
    return {
        "outcome": outcome,
        "cancelledDelta": cancelled_delta,
        "completedDelta": completed_delta,
    }


def validate_websocket_search_cancellation_delta(
    before: dict[str, Any],
    after: dict[str, Any],
) -> dict[str, int]:
    delta = classify_websocket_search_outcome_delta(before, after)
    if delta["outcome"] != "cancelled":
        raise HarnessError("server outcome counters did not prove cancellation before search completion")
    return {"cancelledDelta": 1, "completedDelta": 0}


def wait_for_http_call_cleanup(
    read_snapshot: Callable[[], dict[str, Any]],
    operation_completed: threading.Event,
    *,
    observer_active_calls: int = 1,
    require_websocket_search_idle: bool = False,
    timeout: float = 10,
    poll_interval: float = 0.02,
) -> dict[str, Any]:
    """Require target completion and the diagnostics observer to be the only active HTTP call."""
    if observer_active_calls not in range(1, 65):
        raise HarnessError("cleanup barrier threshold is outside its safety bound")
    if timeout <= 0 or timeout > 120 or poll_interval < 0.001 or poll_interval > 1:
        raise HarnessError("cleanup barrier timing is outside its safety bound")
    started = time.monotonic()
    polls = 0
    while time.monotonic() - started < timeout:
        snapshot = read_snapshot()
        polls += 1
        active = snapshot.get("activeHttpCalls")
        pending = snapshot.get("pendingSessions")
        active_processing = snapshot.get("webSocketSearchActive") if require_websocket_search_idle else 0
        if isinstance(active, bool) or not isinstance(active, int) or active < 1 or active > 64:
            raise HarnessError("diagnostics returned an invalid active HTTP call count")
        if isinstance(pending, bool) or not isinstance(pending, int) or pending < 0:
            raise HarnessError("diagnostics returned an invalid pending session count")
        if (
            isinstance(active_processing, bool)
            or not isinstance(active_processing, int)
            or active_processing < 0
            or active_processing > 64
        ):
            raise HarnessError("diagnostics returned an invalid active WebSocket search count")
        if (
            operation_completed.is_set()
            and active == observer_active_calls
            and pending == 0
            and active_processing == 0
        ):
            return {
                "observed": True,
                "activeHttpCalls": active,
                "activeWebSocketSearches": active_processing,
                "pendingSessions": pending,
                "polls": polls,
                "clientWallSeconds": round(time.monotonic() - started, 6),
            }
        time.sleep(min(poll_interval, max(0.0, timeout - (time.monotonic() - started))))
    raise HarnessError("target operation did not reach the diagnostics cleanup barrier")


def call_tool(client: McpClient, name: str, arguments: dict[str, Any], timeout: float = 180) -> tuple[dict[str, Any], float]:
    started = time.perf_counter()
    response = client.rpc("tools/call", {"name": name, "arguments": arguments}, timeout=timeout)
    elapsed = time.perf_counter() - started
    return structured_content(response), elapsed


def websocket_search_count(value: dict[str, Any], field: str) -> int:
    """Read a non-negative count while honoring omitted Kotlin serialization defaults."""
    raw = value.get(field, 0)
    if isinstance(raw, bool) or not isinstance(raw, int) or raw < 0:
        raise HarnessError("WebSocket search returned invalid bounded accounting")
    return raw


def websocket_search_flag(value: dict[str, Any], field: str) -> bool:
    """Read a Boolean while honoring omitted Kotlin serialization defaults."""
    raw = value.get(field, False)
    if not isinstance(raw, bool):
        raise HarnessError("WebSocket search returned invalid bounded state")
    return raw


def bounded_search_summary(value: dict[str, Any], elapsed: float) -> dict[str, Any]:
    return {
        "status": value.get("status"),
        "returned": websocket_search_count(value, "returned"),
        "scanned": websocket_search_count(value, "scanned"),
        "scanLimitReached": websocket_search_flag(value, "scanLimitReached"),
        "contentLimitReached": websocket_search_flag(value, "contentLimitReached"),
        "hasMore": websocket_search_flag(value, "hasMore"),
        "nextCursorPresent": bool(value.get("nextCursor")),
        "clientWallSeconds": round(elapsed, 6),
    }


def _read_until(sock: socket.socket, marker: bytes = b"\r\n\r\n", limit: int = 65_536) -> bytes:
    data = bytearray()
    while marker not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data.extend(chunk)
        if len(data) > limit:
            raise HarnessError("loopback fixture header exceeded its limit")
    return bytes(data)


def _recv_exact(sock: socket.socket, length: int) -> bytes:
    output = bytearray()
    while len(output) < length:
        chunk = sock.recv(length - len(output))
        if not chunk:
            raise HarnessError("loopback WebSocket closed unexpectedly")
        output.extend(chunk)
    return bytes(output)


def _recv_frame(sock: socket.socket) -> tuple[int, bytes]:
    first, second = _recv_exact(sock, 2)
    opcode = first & 0x0F
    masked = bool(second & 0x80)
    length = second & 0x7F
    if length == 126:
        length = struct.unpack("!H", _recv_exact(sock, 2))[0]
    elif length == 127:
        length = struct.unpack("!Q", _recv_exact(sock, 8))[0]
    if length > 64 * 1024:
        raise HarnessError("loopback WebSocket frame exceeded its limit")
    mask = _recv_exact(sock, 4) if masked else None
    payload = _recv_exact(sock, length)
    if mask:
        payload = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
    return opcode, payload


def _send_frame(sock: socket.socket, payload: bytes, *, opcode: int = 1, masked: bool = False) -> None:
    if len(payload) >= 65_536:
        raise HarnessError("loopback WebSocket frame exceeded its limit")
    first = 0x80 | opcode
    if len(payload) < 126:
        second = len(payload)
        extension = b""
    else:
        second = 126
        extension = struct.pack("!H", len(payload))
    mask = os.urandom(4) if masked else b""
    if masked:
        second |= 0x80
        payload = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
    sock.sendall(bytes((first, second)) + extension + mask + payload)


def run_websocket_fixture(
    *,
    message_count: int,
    marker: str,
    proxy_port: int,
    target_port: int,
    safety_check: Callable[[], None] | None = None,
) -> tuple[int, int, float]:
    if message_count < 0 or message_count > 50_000:
        raise HarnessError("fixture message count is outside its per-stage safety bound")
    if proxy_port not in range(1, 65_536) or target_port not in range(1, 65_536) or proxy_port == target_port:
        raise HarnessError("fixture ports are invalid")
    server_ready = threading.Event()
    stop_server = threading.Event()
    server_errors: list[Exception] = []
    fixture_sockets: list[socket.socket] = []
    fixture_sockets_lock = threading.Lock()

    def serve() -> None:
        try:
            with socket.socket() as listener:
                with fixture_sockets_lock:
                    fixture_sockets.append(listener)
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.bind(("127.0.0.1", target_port))
                listener.listen(1)
                listener.settimeout(0.25)
                server_ready.set()
                connection = None
                while connection is None and not stop_server.is_set():
                    try:
                        connection, _ = listener.accept()
                    except socket.timeout:
                        continue
                if connection is None:
                    return
                with fixture_sockets_lock:
                    fixture_sockets.append(connection)
                with connection:
                    connection.settimeout(30)
                    headers = _read_until(connection).decode("latin-1")
                    key = next(
                        (line.split(":", 1)[1].strip() for line in headers.split("\r\n") if line.lower().startswith("sec-websocket-key:")),
                        None,
                    )
                    if not key:
                        raise HarnessError("loopback WebSocket request omitted its key")
                    accept = base64.b64encode(hashlib.sha1((key + WEBSOCKET_GUID).encode()).digest()).decode()
                    connection.sendall(
                        (
                            "HTTP/1.1 101 Switching Protocols\r\n"
                            "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                            f"Sec-WebSocket-Accept: {accept}\r\n\r\n"
                        ).encode()
                    )
                    for _ in range(message_count):
                        opcode, payload = _recv_frame(connection)
                        if opcode not in {1, 2}:
                            raise HarnessError("loopback fixture received an unexpected frame")
                        _send_frame(connection, b"echo:" + payload, opcode=opcode)
                    try:
                        _send_frame(connection, b"", opcode=8)
                    except OSError:
                        pass
        except Exception as error:  # returned to the main thread without serializing details
            server_errors.append(error)
            server_ready.set()

    server = threading.Thread(target=serve, name="LiveScaleLoopbackFixture", daemon=True)
    server.start()
    if not server_ready.wait(5) or server_errors:
        raise HarnessError("loopback WebSocket fixture did not start")

    started = time.perf_counter()
    echoes = 0
    try:
        with socket.create_connection(("127.0.0.1", proxy_port), timeout=10) as client:
            client.settimeout(30)
            key = base64.b64encode(os.urandom(16)).decode()
            request = (
                f"GET http://127.0.0.1:{target_port}/independent-mcp-scale HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{target_port}\r\n"
                "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
            )
            client.sendall(request.encode())
            response = _read_until(client)
            if b" 101 " not in response.split(b"\r\n", 1)[0]:
                raise HarnessError("Burp proxy did not complete the loopback WebSocket upgrade")
            for index in range(message_count):
                payload = f"{marker}-{index:05d}".encode()
                _send_frame(client, payload, masked=True)
                opcode, echoed = _recv_frame(client)
                if opcode != 1 or echoed != b"echo:" + payload:
                    raise HarnessError("loopback WebSocket echo verification failed")
                echoes += 1
                if safety_check is not None and index % 512 == 0:
                    safety_check()
            try:
                _send_frame(client, b"", opcode=8, masked=True)
            except OSError:
                pass
    finally:
        stop_server.set()
        with fixture_sockets_lock:
            sockets_to_close = list(reversed(fixture_sockets))
        for fixture_socket in sockets_to_close:
            try:
                fixture_socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                fixture_socket.close()
            except OSError:
                pass
        server.join(5)
        if server.is_alive() or server_errors:
            raise HarnessError("loopback WebSocket fixture did not stop cleanly")
    return message_count, echoes, time.perf_counter() - started


def _open_canonical_directory(path: pathlib.Path) -> int:
    canonical = path.resolve(strict=True)
    if not canonical.is_absolute():
        raise HarnessError("output parent must resolve to an absolute directory")
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(canonical.anchor, flags)
    try:
        for part in canonical.parts[1:]:
            next_descriptor = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def write_private_json(
    output: pathlib.Path,
    report: dict[str, Any],
    *,
    forbidden_values: tuple[str, ...] = (),
) -> None:
    if output.exists() or output.is_symlink():
        raise HarnessError("output path must not already exist")
    if output.parent.is_symlink():
        raise HarnessError("output parent must not be a symlink")
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if output.parent.is_symlink():
        raise HarnessError("output parent must not be a symlink")
    serialized = json.dumps(report, indent=2, sort_keys=True) + "\n"
    for value in forbidden_values:
        if value and value in serialized:
            raise HarnessError("private runtime value reached the diagnostic report")
    if any(term in serialized.lower() for term in ("authorization:", "cookie:", "set-cookie:")):
        raise HarnessError("credential-bearing field reached the diagnostic report")
    parent_descriptor = _open_canonical_directory(output.parent)
    created = False
    try:
        descriptor = os.open(
            output.name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=parent_descriptor,
        )
        created = True
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as destination:
                if destination.write(serialized) != len(serialized):
                    raise HarnessError("private diagnostic report write was incomplete")
                destination.flush()
                os.fsync(destination.fileno())
        except BaseException:
            if created:
                try:
                    os.unlink(output.name, dir_fd=parent_descriptor)
                except OSError:
                    pass
            raise
    finally:
        os.close(parent_descriptor)
