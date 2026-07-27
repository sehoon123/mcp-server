#!/usr/bin/env python3
"""Shared, standard-library-only helpers for opt-in loopback Burp live diagnostics."""

from __future__ import annotations

import base64
import hashlib
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


class HarnessError(RuntimeError):
    """A bounded error safe to put in local diagnostic output."""


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


def read_private_token(path: pathlib.Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise HarnessError("token file must be a regular non-symlink file")
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        raise HarnessError("token file permissions must not grant group or other access")
    token = path.read_text(encoding="utf-8").strip()
    if not 32 <= len(token) <= 128 or any(character.isspace() or ord(character) < 32 or ord(character) == 127 for character in token):
        raise HarnessError("token file does not contain a valid local bearer value")
    return token


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
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
                raw = response.read().decode("utf-8", errors="replace")
                return response.status, dict(response.headers.items()), json.loads(raw) if raw.strip() else None
        except urllib.error.HTTPError as error:
            try:
                raw = error.read().decode("utf-8", errors="replace")
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


def call_tool(client: McpClient, name: str, arguments: dict[str, Any], timeout: float = 180) -> tuple[dict[str, Any], float]:
    started = time.perf_counter()
    response = client.rpc("tools/call", {"name": name, "arguments": arguments}, timeout=timeout)
    elapsed = time.perf_counter() - started
    return structured_content(response), elapsed


def bounded_search_summary(value: dict[str, Any], elapsed: float) -> dict[str, Any]:
    return {
        "status": value.get("status"),
        "returned": value.get("returned"),
        "scanned": value.get("scanned"),
        "scanLimitReached": value.get("scanLimitReached"),
        "contentLimitReached": value.get("contentLimitReached"),
        "hasMore": value.get("hasMore"),
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


def write_private_json(
    output: pathlib.Path,
    report: dict[str, Any],
    *,
    forbidden_values: tuple[str, ...] = (),
) -> None:
    if output.exists() or output.is_symlink():
        raise HarnessError("output path must not already exist")
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    serialized = json.dumps(report, indent=2, sort_keys=True) + "\n"
    for value in forbidden_values:
        if value and value in serialized:
            raise HarnessError("private runtime value reached the diagnostic report")
    if any(term in serialized.lower() for term in ("authorization:", "cookie:", "set-cookie:")):
        raise HarnessError("credential-bearing field reached the diagnostic report")
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as destination:
        destination.write(serialized)
