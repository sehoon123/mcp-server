#!/usr/bin/env python3

from __future__ import annotations

import http.server
import importlib.util
import json
import pathlib
import re
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


def load_script_module(module_name: str, filename: str):
    spec = importlib.util.spec_from_file_location(module_name, SCRIPTS / filename)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def load_scale_module():
    return load_script_module("live_scale", "run-live-websocket-scale.py")


def load_lifecycle_module():
    return load_script_module("live_lifecycle", "run-live-lifecycle-soak.py")


def load_cancellation_module():
    return load_script_module("live_cancellation", "run-live-cancellation-barrier.py")


def load_v412_performance_module():
    return load_script_module("live_v412_performance", "run-live-v412-performance-attribution.py")


def history_diagnostics_text(overrides: dict[str, dict] | None = None) -> str:
    overrides = overrides or {}
    metrics = []
    for name in harness.HISTORY_PERFORMANCE_METRICS:
        value = {
            "metric": name,
            "active": 0,
            "attempts": 0,
            "completed": 0,
            "failed": 0,
            "cancelled": 0,
            "latencyBuckets": [0] * harness.HISTORY_PERFORMANCE_BUCKET_COUNT,
            "totalNanos": 0,
            "maxNanos": 0,
        }
        value.update(overrides.get(name, {}))
        metrics.append(value)
    return json.dumps({"diagnostics": {"historyPerformance": {"metrics": metrics}}})


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

    def test_unauthenticated_probe_is_loopback_bounded(self):
        class Unauthorized(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(401)
                self.end_headers()

            def log_message(self, format, *args):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Unauthorized)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            self.assertEqual(
                401,
                harness.unauthenticated_http_status(f"http://127.0.0.1:{server.server_port}/mcp"),
            )
            with self.assertRaises(harness.HarnessError):
                harness.unauthenticated_http_status("http://example.com:9876/mcp")
            with self.assertRaises(harness.HarnessError):
                harness.unauthenticated_http_status(f"http://127.0.0.1:{server.server_port}/mcp", timeout=31)
        finally:
            server.shutdown()
            server.server_close()

    def test_token_file_must_be_private_regular_and_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            token_file = pathlib.Path(directory) / "token"
            token_file.write_text("a" * 48, encoding="utf-8")
            token_file.chmod(0o600)
            self.assertEqual("a" * 48, harness.read_private_token(token_file))
            token_file.chmod(0o644)
            with self.assertRaises(harness.HarnessError):
                harness.read_private_token(token_file)
            token_file.chmod(0o600)
            link = pathlib.Path(directory) / "token-link"
            link.symlink_to(token_file)
            with self.assertRaises(harness.HarnessError):
                harness.read_private_token(link)

            for invalid in ("a" * 42, "!" * 43, "é" * 43, "a" * 129):
                token_file.write_text(invalid, encoding="utf-8")
                with self.assertRaises(harness.HarnessError):
                    harness.read_private_token(token_file)

    def test_private_json_input_rejects_links_permissions_duplicates_and_structure_abuse(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            private = root / "arguments.json"
            private.write_text('{"operation":"bounded"}', encoding="utf-8")
            private.chmod(0o600)
            self.assertEqual({"operation": "bounded"}, harness.read_private_json_file(private))

            private.chmod(0o644)
            with self.assertRaises(harness.HarnessError):
                harness.read_private_json_file(private)
            private.chmod(0o600)

            link = root / "link.json"
            link.symlink_to(private)
            with self.assertRaises(harness.HarnessError):
                harness.read_private_json_file(link)

            hardlink = root / "hardlink.json"
            hardlink.hardlink_to(private)
            with self.assertRaises(harness.HarnessError):
                harness.read_private_json_file(private)
            hardlink.unlink()

            private.write_text('{"duplicate":1,"duplicate":2}', encoding="utf-8")
            with self.assertRaises(harness.HarnessError):
                harness.read_private_json_file(private)

            private.write_text(json.dumps({"nested": [[[[["value"]]]]]}), encoding="utf-8")
            with self.assertRaises(harness.HarnessError):
                harness.read_private_json_file(private, max_bytes=8)

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

    def test_history_performance_metric_names_match_the_kotlin_wire_enum(self):
        source = (
            SCRIPTS.parent
            / "src/main/kotlin/net/portswigger/mcp/tools/HistoryPerformanceDiagnostics.kt"
        ).read_text(encoding="utf-8")
        match = re.search(
            r"enum class HistoryPerformanceMetric\s*\{(?P<body>.*?)\n\}",
            source,
            flags=re.DOTALL,
        )
        self.assertIsNotNone(match)
        kotlin_names = tuple(
            re.findall(r"^\s*([A-Z][A-Z0-9_]*)\s*,?\s*$", match.group("body"), flags=re.MULTILINE)
        )
        self.assertEqual(harness.HISTORY_PERFORMANCE_METRICS, kotlin_names)

    def test_history_performance_parser_and_quiet_snapshot_difference_are_exact(self):
        before_text = history_diagnostics_text()
        acquisition_buckets = [0] * harness.HISTORY_PERFORMANCE_BUCKET_COUNT
        acquisition_buckets[1] = 1
        processing_buckets = [0] * harness.HISTORY_PERFORMANCE_BUCKET_COUNT
        processing_buckets[2] = 2
        after_text = history_diagnostics_text(
            {
                "RELATED_CORRELATION_MONTOYA_ACQUISITION": {
                    "attempts": 1,
                    "completed": 1,
                    "latencyBuckets": acquisition_buckets,
                    "totalNanos": 7,
                    "maxNanos": 7,
                },
                "RELATED_CORRELATION_EXTENSION_PROCESSING": {
                    "attempts": 2,
                    "completed": 2,
                    "latencyBuckets": processing_buckets,
                    "totalNanos": 11,
                    "maxNanos": 6,
                },
            }
        )

        before = harness.parse_history_performance_snapshot(before_text)
        after = harness.parse_history_performance_snapshot(after_text)
        delta = harness.diff_history_performance_snapshots(
            before,
            after,
            frozenset(
                {
                    "RELATED_CORRELATION_MONTOYA_ACQUISITION",
                    "RELATED_CORRELATION_EXTENSION_PROCESSING",
                }
            ),
        )

        self.assertEqual(1, delta["RELATED_CORRELATION_MONTOYA_ACQUISITION"]["attempts"])
        self.assertEqual(7, delta["RELATED_CORRELATION_MONTOYA_ACQUISITION"]["totalNanos"])
        self.assertEqual(2, delta["RELATED_CORRELATION_EXTENSION_PROCESSING"]["attempts"])
        self.assertEqual(11, delta["RELATED_CORRELATION_EXTENSION_PROCESSING"]["totalNanos"])
        self.assertEqual(6, delta["RELATED_CORRELATION_EXTENSION_PROCESSING"]["maxNanosAfter"])

    def test_history_performance_parser_rejects_schema_counter_and_bucket_drift(self):
        valid = json.loads(history_diagnostics_text())
        mutations = []

        missing_metric = json.loads(json.dumps(valid))
        missing_metric["diagnostics"]["historyPerformance"]["metrics"].pop()
        mutations.append(missing_metric)

        reordered = json.loads(json.dumps(valid))
        reordered_metrics = reordered["diagnostics"]["historyPerformance"]["metrics"]
        reordered_metrics[0], reordered_metrics[1] = reordered_metrics[1], reordered_metrics[0]
        mutations.append(reordered)

        extra_field = json.loads(json.dumps(valid))
        extra_field["diagnostics"]["historyPerformance"]["metrics"][0]["private"] = "value"
        mutations.append(extra_field)

        for field, value in (("attempts", True), ("completed", -1), ("totalNanos", (1 << 63) - 1)):
            invalid = json.loads(json.dumps(valid))
            invalid["diagnostics"]["historyPerformance"]["metrics"][0][field] = value
            mutations.append(invalid)

        wrong_buckets = json.loads(json.dumps(valid))
        wrong_buckets["diagnostics"]["historyPerformance"]["metrics"][0]["latencyBuckets"].pop()
        mutations.append(wrong_buckets)

        inconsistent = json.loads(json.dumps(valid))
        inconsistent_metric = inconsistent["diagnostics"]["historyPerformance"]["metrics"][0]
        inconsistent_metric.update(attempts=1, completed=1, totalNanos=1, maxNanos=2)
        inconsistent_metric["latencyBuckets"][0] = 1
        mutations.append(inconsistent)

        active_overflow = json.loads(json.dumps(valid))
        active_overflow["diagnostics"]["historyPerformance"]["metrics"][0]["active"] = 65
        mutations.append(active_overflow)

        for value in mutations:
            with self.subTest(value=value):
                with self.assertRaises(harness.HarnessError):
                    harness.parse_history_performance_snapshot(json.dumps(value))

    def test_history_performance_difference_rejects_contamination_regression_and_active_boundaries(self):
        before = harness.parse_history_performance_snapshot(history_diagnostics_text())
        target_buckets = [1] + [0] * (harness.HISTORY_PERFORMANCE_BUCKET_COUNT - 1)
        target_name = "SCANNER_DELTA_MONTOYA_ACQUISITION"
        processing_name = "SCANNER_DELTA_EXTENSION_PROCESSING"
        valid_after = harness.parse_history_performance_snapshot(
            history_diagnostics_text(
                {
                    target_name: {
                        "attempts": 1,
                        "completed": 1,
                        "latencyBuckets": target_buckets,
                        "totalNanos": 1,
                        "maxNanos": 1,
                    },
                    processing_name: {
                        "attempts": 1,
                        "completed": 1,
                        "latencyBuckets": target_buckets,
                        "totalNanos": 1,
                        "maxNanos": 1,
                    },
                }
            )
        )
        expected = frozenset({target_name, processing_name})

        contaminated = json.loads(json.dumps(valid_after))
        contaminated["HTTP_SEARCH_PROCESSING"].update(
            attempts=1,
            completed=1,
            totalNanos=1,
            maxNanos=1,
            latencyBuckets=target_buckets,
        )
        with self.assertRaises(harness.HarnessError):
            harness.diff_history_performance_snapshots(before, contaminated, expected)

        active = json.loads(json.dumps(valid_after))
        active[target_name]["active"] = 1
        with self.assertRaises(harness.HarnessError):
            harness.diff_history_performance_snapshots(before, active, expected)

        regressed_before = json.loads(json.dumps(valid_after))
        with self.assertRaises(harness.HarnessError):
            harness.diff_history_performance_snapshots(regressed_before, before, expected)

    def test_v412_performance_private_arguments_are_bounded_and_mode_specific(self):
        runner = load_v412_performance_module()
        related = {
            "projectId": "private-project-binding",
            "baselineRefs": [{"source": "proxy", "id": "private-ref-one"}],
            "comparisonRefs": [{"source": "site_map", "id": "private-ref-two"}],
            "pathDepth": 2,
            "relatedTraffic": {
                "seedEventIndices": [0],
                "sources": ["proxy", "site_map"],
                "inScopeOnly": True,
                "limit": 8,
            },
        }
        self.assertIs(related, runner.validate_related_arguments(related))
        invalid_related = json.loads(json.dumps(related))
        invalid_related["relatedTraffic"]["seedEventIndices"] = [0, 0]
        with self.assertRaises(harness.HarnessError):
            runner.validate_related_arguments(invalid_related)

        scanner = {
            "count": 50,
            "sinceSnapshotCursor": "private-signed-cursor",
            "summariesOnly": True,
            "severities": ["high", "medium"],
            "newestFirst": False,
        }
        self.assertIs(scanner, runner.validate_scanner_arguments(scanner))
        for replacement in (
            {"cursor": "mixed"},
            {"offset": 1},
            {"summariesOnly": False},
            {"count": 51},
        ):
            invalid_scanner = dict(scanner)
            invalid_scanner.update(replacement)
            with self.assertRaises(harness.HarnessError):
                runner.validate_scanner_arguments(invalid_scanner)

    def test_v412_performance_summaries_retain_only_aggregate_invariants(self):
        runner = load_v412_performance_module()
        project = "private-project-binding"
        arguments = {
            "baselineRefs": [{"source": "proxy", "id": "private-one"}],
            "comparisonRefs": [{"source": "proxy", "id": "private-two"}],
            "relatedTraffic": {"seedEventIndices": [0], "limit": 1},
        }
        related_value = {
            "status": "ok",
            "projectId": project,
            "timeline": [
                {"cohort": "baseline", "ref": {"source": "proxy"}},
                {"cohort": "comparison", "ref": {"source": "proxy"}},
                {"cohort": "related", "ref": {"source": "proxy"}},
            ],
            "relatedTraffic": {
                "seedEventIndices": [0],
                "sources": ["proxy"],
                "requestedLimit": 1,
                "returned": 1,
                "queryCount": 1,
                "candidateSummariesExamined": 3,
                "qualifiedCandidates": 2,
                "basis": "same_service_and_bounded_metadata",
                "identityEstablished": False,
                "truncated": True,
                "matches": [{}],
            },
            "evidence": {
                "ordering": "caller_supplied_then_related_score",
                "chronologyEstablished": False,
                "cohortBoundaryEstablishesTime": False,
                "exactCrossSourceIdentityEstablished": False,
                "probableDuplicatesDeduplicated": False,
                "selectedReferences": 2,
                "relatedReferences": 1,
                "timelineEvents": 3,
                "maxReferences": 32,
                "maxReferencesPerCohort": 16,
                "maxRelatedReferences": 16,
                "maxTimelineEvents": 48,
            },
            "delta": {"baselineRecords": 1, "comparisonRecords": 1},
        }
        related_summary = runner._related_summary(related_value, arguments, project)
        self.assertEqual(1, related_summary["relatedReturned"])
        self.assertEqual(3, related_summary["expectedAcquisitionAttemptsPerCall"])
        self.assertEqual(16, related_summary["expectedProcessingAttemptsPerCall"])
        self.assertNotIn(project, json.dumps(related_summary))
        self.assertNotIn("private-one", json.dumps(related_summary))

        mixed_arguments = json.loads(json.dumps(arguments))
        mixed_arguments["comparisonRefs"][0]["source"] = "site_map"
        mixed_arguments["relatedTraffic"]["sources"] = ["proxy", "site_map"]
        mixed_value = json.loads(json.dumps(related_value))
        mixed_value["timeline"][1]["ref"]["source"] = "site_map"
        mixed_value["timeline"][2]["ref"]["source"] = "site_map"
        mixed_value["relatedTraffic"]["sources"] = ["proxy", "site_map"]
        mixed_summary = runner._related_summary(mixed_value, mixed_arguments, project)
        self.assertEqual(5, mixed_summary["expectedAcquisitionAttemptsPerCall"])
        self.assertEqual(15, mixed_summary["expectedProcessingAttemptsPerCall"])

        invalid_related_value = json.loads(json.dumps(related_value))
        invalid_related_value["relatedTraffic"]["returned"] = 2
        with self.assertRaises(harness.HarnessError):
            runner._related_summary(invalid_related_value, arguments, project)
        changed_fixture_arguments = json.loads(json.dumps(arguments))
        changed_fixture_arguments["relatedTraffic"]["limit"] = 2
        changed_fixture_value = json.loads(json.dumps(related_value))
        changed_fixture_value["relatedTraffic"]["requestedLimit"] = 2
        with self.assertRaisesRegex(harness.HarnessError, "fixture changed"):
            runner._related_summary(changed_fixture_value, changed_fixture_arguments, project)
        zero_work_related = json.loads(json.dumps(related_value))
        zero_work_related["timeline"] = zero_work_related["timeline"][:2]
        zero_work_related["relatedTraffic"].update(
            returned=0,
            candidateSummariesExamined=0,
            qualifiedCandidates=0,
            matches=[],
        )
        zero_work_related["evidence"].update(relatedReferences=0, timelineEvents=2)
        with self.assertRaises(harness.HarnessError):
            runner._related_summary(zero_work_related, arguments, project)

        scanner_value = {
            "status": "ok",
            "projectId": project,
            "deltaMode": True,
            "legacyMode": False,
            "legacyTextTruncated": False,
            "scanLimitReached": True,
            "items": [],
            "returned": 0,
            "scanned": 10_000,
            "snapshotSize": 50_000,
            "hasMore": True,
            "nextDeltaCursor": "private-next-cursor",
            "snapshotCursor": None,
            "delta": {
                "basis": "append_stable_currently_visible_range",
                "baselineSnapshotSize": 40_000,
                "currentSnapshotSize": 50_000,
                "appendedRangeSize": 10_000,
                "regressionEstablished": False,
                "removedOrChangedEstablished": False,
                "completeHistoryEstablished": False,
            },
        }
        scanner_summary = runner._scanner_summary(scanner_value, 50_000, project)
        self.assertEqual(50_000, scanner_summary["snapshotSize"])
        self.assertEqual(1, scanner_summary["expectedAcquisitionAttemptsPerCall"])
        self.assertEqual(1, scanner_summary["expectedProcessingAttemptsPerCall"])
        self.assertNotIn("private-next-cursor", json.dumps(scanner_summary))
        empty_delta = json.loads(json.dumps(scanner_value))
        empty_delta["delta"]["baselineSnapshotSize"] = 50_000
        empty_delta["delta"]["appendedRangeSize"] = 0
        with self.assertRaises(harness.HarnessError):
            runner._scanner_summary(empty_delta, 50_000, project)

        with self.assertRaises(harness.HarnessError):
            runner._assert_report_omits_private_values(
                {"safe": "private-next-cursor"},
                {"private-next-cursor"},
            )

    def test_v412_attributed_phase_time_must_fit_serial_client_wall_time(self):
        runner = load_v412_performance_module()
        phase_deltas = {
            "acquisition": {"totalNanos": 100_000_000},
            "processing": {"totalNanos": 200_000_000},
        }

        self.assertEqual(0.3, runner._attributed_wall_ratio(phase_deltas, [1.0]))
        with self.assertRaises(harness.HarnessError):
            runner._attributed_wall_ratio(phase_deltas, [0.1])

    def test_v412_evidence_retains_only_aggregate_wall_attribution(self):
        runner = load_v412_performance_module()
        evidence = runner._aggregate_measurement_evidence(
            {"returned": 1},
            {"acquisition": {"totalNanos": 1}, "processing": {"totalNanos": 2}},
            0.5,
            100,
            101,
        )

        self.assertEqual(
            {
                "invariants",
                "phaseDeltas",
                "attributedPhaseToClientWallRatio",
                "rssBeforeKiB",
                "rssAfterKiB",
            },
            set(evidence),
        )
        self.assertNotIn(
            '"clientWallSeconds"',
            (SCRIPTS / "run-live-v412-performance-attribution.py").read_text(encoding="utf-8"),
        )

    def test_interruptible_call_reports_socket_abort_without_response_content(self):
        request_received = threading.Event()
        release_response = threading.Event()

        class HangingTool(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                self.rfile.read(length)
                request_received.set()
                release_response.wait(5)
                try:
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"jsonrpc":"2.0","id":1,"result":{"private":"not-retained"}}')
                except OSError:
                    pass

            def log_message(self, format, *args):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), HangingTool)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            client = harness.McpClient(f"http://127.0.0.1:{server.server_port}/mcp", "s" * 48)
            client.session_id = "private-session-value"
            call = harness.InterruptibleMcpToolCall(
                client,
                "search_websocket_messages",
                {"projectId": "private-project-value", "limit": 1},
                request_id=1,
                timeout=10,
            )
            call.start()
            self.assertTrue(request_received.wait(2))
            self.assertTrue(call.abort())
            call.join(2)
            self.assertEqual(
                {"state": "aborted", "httpStatus": None, "jsonRpcResponse": False},
                call.summary(),
            )
            self.assertNotIn("private", str(call.summary()))
        finally:
            release_response.set()
            server.shutdown()
            server.server_close()

    def test_abort_and_delete_sequence_accepts_exactly_one_target_deletion(self):
        runner = load_cancellation_module()

        class FakeCall:
            def __init__(self):
                self.abort_count = 0
                self.join_count = 0

            def abort(self):
                self.abort_count += 1
                return True

            def join(self, timeout):
                self.join_count += 1

            def summary(self):
                return {"state": "aborted", "httpStatus": None, "jsonRpcResponse": False}

        class FakeTarget:
            def __init__(self):
                self.close_count = 0

            def close(self):
                self.close_count += 1
                return 202

        call = FakeCall()
        target = FakeTarget()
        result = runner.abort_and_delete_active_target(call, target)
        self.assertEqual(1, call.abort_count)
        self.assertEqual(1, call.join_count)
        self.assertEqual(1, target.close_count)
        self.assertEqual(202, result["sessionDeleteStatus"])
        self.assertEqual("aborted", result["targetOutcome"]["state"])

    def test_completed_server_work_with_lost_response_is_not_cancellation_proof(self):
        before = {"webSocketSearchCompleted": 4, "webSocketSearchCancelled": 2}
        completed_before_response = {"webSocketSearchCompleted": 5, "webSocketSearchCancelled": 2}
        self.assertEqual(
            {"outcome": "completed", "cancelledDelta": 0, "completedDelta": 1},
            harness.classify_websocket_search_outcome_delta(before, completed_before_response),
        )
        with self.assertRaises(harness.HarnessError):
            harness.validate_websocket_search_cancellation_delta(before, completed_before_response)

        cancelled = {"webSocketSearchCompleted": 4, "webSocketSearchCancelled": 3}
        self.assertEqual(
            {"outcome": "cancelled", "cancelledDelta": 1, "completedDelta": 0},
            harness.classify_websocket_search_outcome_delta(before, cancelled),
        )
        self.assertEqual(
            {"cancelledDelta": 1, "completedDelta": 0},
            harness.validate_websocket_search_cancellation_delta(before, cancelled),
        )
        with self.assertRaises(harness.HarnessError):
            harness.classify_websocket_search_outcome_delta(
                before,
                {"webSocketSearchCompleted": 5, "webSocketSearchCancelled": 3},
            )

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
            "--expected-server-version", "4.11.0-rc.1",
        ]
        for script in ("run-live-websocket-scale.py", "run-live-lifecycle-soak.py"):
            for edition in ("community", "professional"):
                result = subprocess.run(
                    [
                        sys.executable,
                        str(SCRIPTS / script),
                        *common,
                        "--edition", edition,
                    ],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                self.assertEqual(2, result.returncode)
                self.assertIn("--burp-pid", result.stderr)

        for script, extra in (
            ("run-exact-burp-preflight.py", []),
            ("run-live-cancellation-barrier.py", ["--operator-confirmed-data-read-approved"]),
        ):
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPTS / script),
                    "--approved-disposable-project",
                    *extra,
                    "--edition", "community",
                    "--token-file", "missing-token",
                    "--output", "missing-output",
                    "--candidate-jar", "missing-jar",
                    "--expected-jar-sha256", "0" * 64,
                    "--expected-source-commit", "0" * 40,
                    "--expected-server-version", "4.11.0-rc.1",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(2, result.returncode)
            self.assertIn("--burp-pid", result.stderr)

    def test_live_runners_reject_unknown_editions(self):
        common = [
            "--approved-disposable-project",
            "--token-file", "missing-token",
            "--output", "missing-output",
            "--candidate-jar", "missing-jar",
            "--expected-jar-sha256", "0" * 64,
            "--expected-source-commit", "0" * 40,
            "--expected-server-version", "4.11.0-rc.1",
            "--edition", "mixed",
            "--burp-pid", "1",
        ]
        for script in ("run-live-websocket-scale.py", "run-live-lifecycle-soak.py"):
            result = subprocess.run(
                [sys.executable, str(SCRIPTS / script), *common],
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(2, result.returncode)
            self.assertIn("invalid choice", result.stderr)

    def test_fixed_scale_stage_parser_has_no_unbounded_values(self):
        scale = load_scale_module()
        self.assertEqual([10_000, 50_000, 100_000], scale.parse_stages("10000,50000,100000"))
        for value in ("", "1000", "50000,10000", "10000,10000", "100000,200000"):
            with self.assertRaises(Exception):
                scale.parse_stages(value)

    def test_lifecycle_pass_requires_every_supported_protocol_cycle(self):
        lifecycle = load_lifecycle_module()
        covered = {protocol: 1 for protocol in harness.SUPPORTED_PROTOCOLS}
        lifecycle.require_all_protocol_cycles(covered)
        for invalid in (
            {protocol: (0 if index == 0 else 1) for index, protocol in enumerate(harness.SUPPORTED_PROTOCOLS)},
            {protocol: 1 for protocol in harness.SUPPORTED_PROTOCOLS[:-1]},
            {**covered, "unexpected": 1},
            {protocol: True for protocol in harness.SUPPORTED_PROTOCOLS},
        ):
            with self.assertRaises(harness.HarnessError):
                lifecycle.require_all_protocol_cycles(invalid)

    def test_diagnostics_reader_returns_only_fixed_cardinality_fields_and_raw_text(self):
        class Client:
            def rpc(self, method, params):
                self.method = method
                self.params = params
                return {
                    "result": {
                        "contents": [{
                            "text": json.dumps({
                                "diagnostics": {
                                    "activeHttpCalls": 1,
                                    "activeSessions": 1,
                                    "webSocketSearchActive": 0,
                                    "unapprovedFutureField": "not-copied",
                                }
                            })
                        }]
                    }
                }

        client = Client()
        diagnostics, raw = harness.read_bounded_diagnostics(client)
        self.assertEqual("resources/read", client.method)
        self.assertEqual({"uri": "burp://diagnostics"}, client.params)
        self.assertEqual(1, diagnostics["activeHttpCalls"])
        self.assertEqual(1, diagnostics["activeSessions"])
        self.assertEqual(0, diagnostics["webSocketSearchActive"])
        self.assertNotIn("unapprovedFutureField", diagnostics)
        self.assertIn("unapprovedFutureField", raw)

    def test_active_call_barriers_require_observed_concurrency_and_cleanup(self):
        completed = threading.Event()
        snapshots = iter((
            {"activeHttpCalls": 1},
            {"activeHttpCalls": 2},
        ))
        barrier = harness.wait_for_active_http_call_barrier(
            lambda: next(snapshots),
            completed,
            timeout=1,
            poll_interval=0.001,
        )
        self.assertTrue(barrier["observed"])
        self.assertEqual(2, barrier["maximumObservedActiveCalls"])

        processing_snapshots = iter((
            {"activeHttpCalls": 2, "webSocketSearchActive": 0},
            {"activeHttpCalls": 2, "webSocketSearchActive": 1},
        ))
        processing = harness.wait_for_websocket_search_processing_barrier(
            lambda: next(processing_snapshots),
            completed,
            timeout=1,
            poll_interval=0.001,
        )
        self.assertTrue(processing["observed"])
        self.assertEqual(1, processing["maximumObservedActiveWebSocketSearches"])

        completed.set()
        cleanup = harness.wait_for_http_call_cleanup(
            lambda: {
                "activeHttpCalls": 1,
                "pendingSessions": 0,
                "webSocketSearchActive": 0,
            },
            completed,
            require_websocket_search_idle=True,
            timeout=1,
            poll_interval=0.001,
        )
        self.assertTrue(cleanup["observed"])
        self.assertEqual(0, cleanup["activeWebSocketSearches"])

    def test_active_call_barrier_does_not_treat_early_completion_as_proof(self):
        completed = threading.Event()
        completed.set()
        with self.assertRaises(harness.HarnessError):
            harness.wait_for_active_http_call_barrier(
                lambda: {"activeHttpCalls": 2},
                completed,
                timeout=1,
                poll_interval=0.001,
            )

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
