#!/usr/bin/env python3
"""Prove caller-disconnect cleanup only after observing a real bounded history read in flight."""

from __future__ import annotations

import argparse
import json
import pathlib
import secrets
import subprocess
import sys
from typing import Any

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from exact_smoke_contract import EDITION_CATALOG_COUNTS, validate_catalog, validate_release_identity  # noqa: E402
from live_mcp_harness import (  # noqa: E402
    HarnessError,
    InterruptibleMcpToolCall,
    McpClient,
    bounded_rss_snapshot,
    bounded_system_failure,
    call_tool,
    enforce_rss_limit,
    read_bounded_diagnostics,
    read_private_token,
    read_project_id,
    sha256_file,
    validate_websocket_search_cancellation_delta,
    wait_for_active_http_call_barrier,
    wait_for_http_call_cleanup,
    websocket_search_count,
    write_private_json,
)


def git_output(root: pathlib.Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=True,
        capture_output=True,
        text=True,
        timeout=15,
    )
    return result.stdout.strip()


def catalog_items(response: Any, key: str) -> list[dict[str, Any]]:
    try:
        items = response["result"][key]
    except (KeyError, TypeError):
        raise HarnessError("MCP catalog response was malformed")
    if not isinstance(items, list) or any(not isinstance(item, dict) for item in items):
        raise HarnessError("MCP catalog response was malformed")
    return items


def verify_server(client: McpClient, expected_version: str) -> None:
    initialized = client.initialize()
    server_info = ((initialized.get("result") or {}).get("serverInfo") or {})
    if server_info.get("name") != "independent-mcp-bridge" or server_info.get("version") != expected_version:
        raise HarnessError("unexpected MCP server identity")


def close_client(client: McpClient | None) -> bool:
    if client is None or client.session_id is None:
        return True
    try:
        return client.close() in {200, 202}
    except (HarnessError, OSError):
        return False


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--approved-disposable-project", action="store_true", required=True)
    parser.add_argument("--operator-confirmed-data-read-approved", action="store_true", required=True)
    parser.add_argument("--edition", choices=tuple(EDITION_CATALOG_COUNTS), required=True)
    parser.add_argument("--token-file", required=True, type=pathlib.Path)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument("--candidate-jar", required=True, type=pathlib.Path)
    parser.add_argument("--expected-jar-sha256", required=True)
    parser.add_argument("--expected-source-commit", required=True)
    parser.add_argument("--expected-server-version", required=True)
    parser.add_argument("--endpoint", default="http://127.0.0.1:9876/mcp")
    parser.add_argument("--burp-pid", type=int, required=True)
    parser.add_argument("--max-rss-mib", type=int, default=6144)
    parser.add_argument("--attempts", type=int, default=25)
    parser.add_argument("--barrier-timeout-seconds", type=float, default=2.0)
    args = parser.parse_args()

    validate_release_identity(
        args.expected_source_commit,
        args.expected_jar_sha256,
        args.expected_server_version,
    )
    if args.max_rss_mib < 1024 or args.max_rss_mib > 32768:
        raise HarnessError("RSS safety limit is outside the accepted range")
    if args.attempts not in range(1, 51):
        raise HarnessError("cancellation attempt count is outside its safety bound")
    if args.barrier_timeout_seconds < 0.05 or args.barrier_timeout_seconds > 10:
        raise HarnessError("cancellation barrier timeout is outside its safety bound")
    if args.candidate_jar.is_symlink() or not args.candidate_jar.is_file():
        raise HarnessError("candidate JAR must be a regular non-symlink file")
    jar_sha256 = sha256_file(args.candidate_jar)
    if jar_sha256 != args.expected_jar_sha256:
        raise HarnessError("candidate JAR checksum does not match")
    source_root = pathlib.Path(__file__).resolve().parent.parent
    source_commit = git_output(source_root, "rev-parse", "--verify", "HEAD")
    if source_commit != args.expected_source_commit:
        raise HarnessError("source commit does not match the approved candidate")
    if git_output(source_root, "status", "--porcelain", "--untracked-files=normal"):
        raise HarnessError("cancellation proof requires a clean source checkout")

    token = read_private_token(args.token_file)
    max_rss_kib = args.max_rss_mib * 1024
    marker = "mcp-cancel-" + secrets.token_hex(24)
    target: McpClient | None = None
    observer: McpClient | None = None
    verifier: McpClient | None = None
    active_call: InterruptibleMcpToolCall | None = None
    project_id = ""
    sessions_created = 0
    sessions_deleted = 0
    counted_clients: set[int] = set()
    private_session_ids: list[str] = []
    report: dict[str, Any] = {
        "schemaVersion": 1,
        "status": "failed",
        "edition": args.edition,
        "sourceCommit": source_commit,
        "candidateJarSha256": jar_sha256,
        "candidateJarName": args.candidate_jar.name,
        "expectedServerVersion": args.expected_server_version,
        "protocolVersion": "2025-11-25",
        "operation": "bounded WebSocket history search with a private no-match marker",
        "requestedAttempts": args.attempts,
        "completedBeforeBarrierAttempts": 0,
        "projectIdentifierRecorded": False,
        "sessionIdentifierRecorded": False,
        "searchMarkerRecorded": False,
        "rawTrafficRecorded": False,
        "timeoutTreatedAsCancellationProof": False,
        "ctrlCTreatedAsCancellationProof": False,
        "rssStartKiB": enforce_rss_limit(args.burp_pid, max_rss_kib),
        "latencyClaimMade": False,
    }
    try:
        target = McpClient(args.endpoint, token)
        verify_server(target, args.expected_server_version)
        counted_clients.add(id(target))
        sessions_created += 1
        if target.session_id:
            private_session_ids.append(target.session_id)
        project_id = read_project_id(target)

        observer = McpClient(args.endpoint, token)
        verify_server(observer, args.expected_server_version)
        counted_clients.add(id(observer))
        sessions_created += 1
        if observer.session_id:
            private_session_ids.append(observer.session_id)
        if read_project_id(observer) != project_id:
            raise HarnessError("observer and target sessions do not share the disposable project")
        tools = catalog_items(observer.rpc("tools/list", {}), "tools")
        prompts = catalog_items(observer.rpc("prompts/list", {}), "prompts")
        resources = catalog_items(observer.rpc("resources/list", {}), "resources")
        report["catalog"] = validate_catalog(args.edition, tools, prompts, resources)
        initial_diagnostics, initial_diagnostics_text = read_bounded_diagnostics(observer)
        if initial_diagnostics.get("loadedArtifactSha256") != jar_sha256:
            raise HarnessError("running extension artifact does not match the approved candidate JAR")
        if initial_diagnostics.get("activeSessions") != 2 or initial_diagnostics.get("pendingSessions") != 0:
            raise HarnessError("cancellation proof requires exactly the target and observer sessions")
        if initial_diagnostics.get("activeEventStreams") != 0:
            raise HarnessError("cancellation proof requires no active event stream")
        if any(value in initial_diagnostics_text for value in (token, project_id, *private_session_ids)):
            raise HarnessError("private runtime value reached diagnostics")
        report["loadedArtifactSha256"] = "matched"

        precondition, _ = call_tool(
            target,
            "search_websocket_messages",
            {
                "projectId": project_id,
                "regex": marker,
                "caseSensitive": True,
                "limit": 1,
                "newestFirst": True,
            },
            timeout=180,
        )
        scanned = websocket_search_count(precondition, "scanned")
        if precondition.get("status") != "ok" or scanned != 10_000 or websocket_search_count(precondition, "returned") != 0:
            raise HarnessError("cancellation proof requires a clean 10,000-message no-match search precondition")
        report["precondition"] = {
            "status": "passed",
            "scanned": scanned,
            "returned": 0,
        }

        def snapshot() -> dict[str, Any]:
            assert observer is not None
            value, _ = read_bounded_diagnostics(observer)
            return value

        barrier: dict[str, Any] | None = None
        selected_outcomes_before: dict[str, Any] | None = None
        for attempt in range(1, args.attempts + 1):
            outcomes_before = snapshot()
            active_call = InterruptibleMcpToolCall(
                target,
                "search_websocket_messages",
                {
                    "projectId": project_id,
                    "regex": marker,
                    "caseSensitive": True,
                    "limit": 1,
                    "newestFirst": True,
                },
                request_id=100_000 + attempt,
                timeout=180,
            )
            active_call.start()
            try:
                barrier = wait_for_active_http_call_barrier(
                    snapshot,
                    active_call.completed,
                    minimum_active_calls=2,
                    timeout=args.barrier_timeout_seconds,
                    poll_interval=0.001,
                )
            except HarnessError:
                if active_call.completed.is_set():
                    active_call.join(2)
                    report["completedBeforeBarrierAttempts"] += 1
                    active_call = None
                    continue
                active_call.abort()
                active_call.join(10)
                raise
            report["barrierAttempt"] = attempt
            selected_outcomes_before = outcomes_before
            break
        if barrier is None or active_call is None or selected_outcomes_before is None:
            raise HarnessError("no target read remained active long enough for the diagnostics barrier")
        report["activeCallBarrier"] = barrier

        socket_abort_issued = active_call.abort()
        active_call.join(10)
        target_outcome = active_call.summary()
        report["targetOutcome"] = target_outcome
        report["socketAbortIssuedAfterBarrier"] = socket_abort_issued
        if not socket_abort_issued or target_outcome.get("state") != "aborted":
            raise HarnessError("target read completed instead of proving caller-disconnect cancellation")
        report["cleanupBarrier"] = wait_for_http_call_cleanup(
            snapshot,
            active_call.completed,
            timeout=10,
            poll_interval=0.01,
        )
        outcomes_after = snapshot()
        report["serverCancellationOutcome"] = validate_websocket_search_cancellation_delta(
            selected_outcomes_before,
            outcomes_after,
        )
        active_call = None

        if close_client(target):
            sessions_deleted += 1
            target = None
        else:
            raise HarnessError("target session DELETE failed after cancellation")
        diagnostics, _ = read_bounded_diagnostics(observer)
        if diagnostics.get("activeSessions") != 1 or diagnostics.get("pendingSessions") != 0:
            raise HarnessError("target session did not leave the observer-only session plateau")
        if diagnostics.get("activeEventStreams") != 0 or diagnostics.get("sessionsWithApprovals") != 0:
            raise HarnessError("cancellation left event stream or approval state behind")
        if close_client(observer):
            sessions_deleted += 1
            observer = None
        else:
            raise HarnessError("observer session DELETE failed after cancellation")

        verifier = McpClient(args.endpoint, token)
        verify_server(verifier, args.expected_server_version)
        counted_clients.add(id(verifier))
        sessions_created += 1
        if verifier.session_id:
            private_session_ids.append(verifier.session_id)
        if read_project_id(verifier) != project_id:
            raise HarnessError("fresh verifier session did not bind to the same disposable project")
        diagnostics, _ = read_bounded_diagnostics(verifier)
        if diagnostics.get("activeSessions") != 1 or diagnostics.get("pendingSessions") != 0:
            raise HarnessError("fresh verifier did not observe a single-session plateau")
        if diagnostics.get("activeEventStreams") != 0 or diagnostics.get("sessionsWithApprovals") != 0:
            raise HarnessError("fresh verifier observed leaked event stream or approval state")
        report["freshSessionAfterCancellation"] = "passed"
        if close_client(verifier):
            sessions_deleted += 1
            verifier = None
        else:
            raise HarnessError("fresh verifier session DELETE failed")
        report["status"] = "passed"
    except HarnessError as error:
        report["failure"] = str(error)
    except (OSError, subprocess.SubprocessError) as error:
        report["failure"] = bounded_system_failure(error)
    finally:
        if active_call is not None and not active_call.completed.is_set():
            active_call.abort()
            try:
                active_call.join(10)
            except HarnessError:
                report.setdefault("cleanupFailure", "active call did not stop")
        for client in (target, observer, verifier):
            if client is not None and client.session_id is not None:
                if client.session_id not in private_session_ids:
                    private_session_ids.append(client.session_id)
                if id(client) not in counted_clients:
                    counted_clients.add(id(client))
                    sessions_created += 1
                if close_client(client):
                    sessions_deleted += 1
                else:
                    report.setdefault("cleanupFailure", "one MCP session DELETE failed")
        final_rss, rss_failure = bounded_rss_snapshot(args.burp_pid, max_rss_kib)
        report["rssEndKiB"] = final_rss
        if rss_failure is not None:
            report["status"] = "failed"
            report["rssObservationFailure"] = rss_failure
            report.setdefault("failure", rss_failure)
        report["sessionsCreated"] = sessions_created
        report["sessionsDeleted"] = sessions_deleted
        report["allCreatedSessionsDeleted"] = sessions_created == sessions_deleted
        if not report["allCreatedSessionsDeleted"]:
            report["status"] = "failed"
            report.setdefault("failure", "not every created session was deleted")
        write_private_json(
            args.output,
            report,
            forbidden_values=tuple(
                value
                for value in (token, project_id, marker, *private_session_ids, str(pathlib.Path.home()))
                if value
            ),
        )

    print(
        json.dumps(
            {
                "status": report["status"],
                "barrierObserved": "activeCallBarrier" in report,
                "outputSha256": sha256_file(args.output),
            },
            sort_keys=True,
        )
    )
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (HarnessError, OSError, subprocess.SubprocessError) as error:
        print(f"live cancellation proof refused: {type(error).__name__}", file=sys.stderr)
        raise SystemExit(2)
