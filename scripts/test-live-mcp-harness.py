#!/usr/bin/env python3

from __future__ import annotations

import http.server
import importlib.util
import json
import pathlib
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

SCRIPTS = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))
import live_mcp_harness as harness  # noqa: E402


def load_scale_module():
    spec = importlib.util.spec_from_file_location("live_scale", SCRIPTS / "run-live-websocket-scale.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class LiveMcpHarnessContractTest(unittest.TestCase):
    def test_loopback_endpoint_validation_rejects_external_and_ambiguous_urls(self):
        self.assertEqual(
            "http://127.0.0.1:9876/mcp",
            harness.validate_loopback_endpoint("http://127.0.0.1:9876/mcp"),
        )
        for value in (
            "https://127.0.0.1:9876/mcp",
            "http://example.com:9876/mcp",
            "http://127.0.0.1:9876/other",
            "http://user@127.0.0.1:9876/mcp",
        ):
            with self.assertRaises(harness.HarnessError):
                harness.validate_loopback_endpoint(value)

    def test_token_file_must_be_private_regular_and_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            token_file = pathlib.Path(directory) / "token"
            token_file.write_text("a" * 48, encoding="utf-8")
            token_file.chmod(0o600)
            self.assertEqual("a" * 48, harness.read_private_token(token_file))
            token_file.chmod(0o644)
            with self.assertRaises(harness.HarnessError):
                harness.read_private_token(token_file)

    def test_private_report_is_exclusive_redacted_and_mode_600(self):
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory) / "evidence" / "result.json"
            harness.write_private_json(output, {"status": "passed"}, forbidden_values=("secret-value",))
            self.assertEqual({"status": "passed"}, json.loads(output.read_text(encoding="utf-8")))
            self.assertEqual(0o600, stat.S_IMODE(output.stat().st_mode))
            with self.assertRaises(harness.HarnessError):
                harness.write_private_json(output, {"status": "again"})

            leaked = pathlib.Path(directory) / "leaked.json"
            with self.assertRaises(harness.HarnessError):
                harness.write_private_json(leaked, {"value": "secret-value"}, forbidden_values=("secret-value",))
            self.assertFalse(leaked.exists())

    def test_http_redirect_is_returned_without_forwarding_the_bearer(self):
        forwarded_authorizations = []

        class Destination(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                forwarded_authorizations.append(self.headers.get("Authorization"))
                self.send_response(200)
                self.end_headers()

            def log_message(self, format, *args):
                pass

        destination = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Destination)

        class Redirect(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                self.send_response(307)
                self.send_header("Location", f"http://127.0.0.1:{destination.server_port}/capture")
                self.end_headers()

            def log_message(self, format, *args):
                pass

        redirect = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Redirect)
        threads = [
            threading.Thread(target=destination.serve_forever, daemon=True),
            threading.Thread(target=redirect.serve_forever, daemon=True),
        ]
        for thread in threads:
            thread.start()
        try:
            client = harness.McpClient(
                f"http://127.0.0.1:{redirect.server_port}/mcp",
                "s" * 48,
            )
            status, _, _ = client.request({"probe": True}, include_session=False)
            self.assertEqual(307, status)
            self.assertEqual([], forwarded_authorizations)
        finally:
            redirect.shutdown()
            destination.shutdown()
            redirect.server_close()
            destination.server_close()

    def test_live_runners_require_a_burp_pid(self):
        common = [
            "--approved-disposable-project",
            "--token-file", "missing-token",
            "--output", "missing-output",
            "--candidate-jar", "missing-jar",
            "--expected-jar-sha256", "0" * 64,
            "--expected-source-commit", "0" * 40,
            "--expected-server-version", "4.10.0-rc.1",
            "--expected-tools", "31",
            "--expected-prompts", "5",
        ]
        for script in ("run-live-websocket-scale.py", "run-live-lifecycle-soak.py"):
            result = subprocess.run(
                [sys.executable, str(SCRIPTS / script), *common],
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(2, result.returncode)
            self.assertIn("--burp-pid", result.stderr)

    def test_fixed_scale_stage_parser_has_no_unbounded_values(self):
        scale = load_scale_module()
        self.assertEqual([10_000, 50_000, 100_000], scale.parse_stages("10000,50000,100000"))
        for value in ("", "1000", "50000,10000", "10000,10000", "100000,200000"):
            with self.assertRaises(Exception):
                scale.parse_stages(value)

    def test_websocket_search_omitted_defaults_are_valid_zero_and_false(self):
        summary = harness.bounded_search_summary({"status": "ok", "scanned": 10_000}, 0.25)
        self.assertEqual(0, summary["returned"])
        self.assertEqual(10_000, summary["scanned"])
        self.assertFalse(summary["scanLimitReached"])
        self.assertFalse(summary["contentLimitReached"])
        self.assertFalse(summary["hasMore"])
        with self.assertRaises(harness.HarnessError):
            harness.websocket_search_count({"returned": True}, "returned")
        with self.assertRaises(harness.HarnessError):
            harness.websocket_search_flag({"hasMore": 1}, "hasMore")

    def test_system_failures_are_classified_without_exception_details(self):
        self.assertEqual(
            "live diagnostic operation timed out",
            harness.bounded_system_failure(TimeoutError("private endpoint and path")),
        )
        self.assertEqual(
            "live diagnostic operation timed out",
            harness.bounded_system_failure(subprocess.TimeoutExpired(["private-command"], 1)),
        )
        self.assertEqual(
            "live diagnostic subprocess failed",
            harness.bounded_system_failure(subprocess.CalledProcessError(1, ["private-command"])),
        )
        self.assertEqual(
            "live diagnostic system operation failed",
            harness.bounded_system_failure(OSError("private filesystem path")),
        )

    def test_final_rss_snapshot_is_bounded_after_timeout_and_limit_failure(self):
        with mock.patch.object(
            harness,
            "current_rss_kib",
            side_effect=subprocess.TimeoutExpired(["private-command"], 1),
        ):
            self.assertEqual(
                (None, "live diagnostic operation timed out"),
                harness.bounded_rss_snapshot(123, 1024),
            )
        with mock.patch.object(harness, "current_rss_kib", return_value=2048):
            self.assertEqual(
                (2048, "Burp process RSS exceeded the configured safety limit"),
                harness.bounded_rss_snapshot(123, 1024),
            )

    def test_fixture_connection_failure_closes_its_listener_thread(self):
        def unused_port():
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                return listener.getsockname()[1]

        proxy_port = unused_port()
        target_port = unused_port()
        while target_port == proxy_port:
            target_port = unused_port()
        started = time.monotonic()
        with self.assertRaises((harness.HarnessError, OSError)):
            harness.run_websocket_fixture(
                message_count=1,
                marker="fixture-cleanup",
                proxy_port=proxy_port,
                target_port=target_port,
            )
        self.assertLess(time.monotonic() - started, 6)
        self.assertFalse(any(thread.name == "LiveScaleLoopbackFixture" and thread.is_alive() for thread in threading.enumerate()))

    def test_websocket_frame_helpers_round_trip_without_retaining_payload(self):
        first, second = socket.socketpair()
        try:
            harness._send_frame(first, b"bounded", masked=True)
            opcode, payload = harness._recv_frame(second)
            self.assertEqual(1, opcode)
            self.assertEqual(b"bounded", payload)
        finally:
            first.close()
            second.close()


if __name__ == "__main__":
    unittest.main()
