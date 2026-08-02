#!/usr/bin/env python3
"""Prove bounded WebSocket cancellation after a processing barrier and caller disconnect."""

from __future__ import annotations

import argparse
import json
import pathlib
import secrets
import subprocess
import sys
from typing import Any

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from exact_smoke_contract import (  # noqa: E402
    EDITION_CATALOG_COUNTS,
    catalog_items,
    requires_v412_catalog_schema,
    validate_catalog,
    validate_release_identity,
)
from live_mcp_harness import (  # noqa: E402
    HarnessError,
    InterruptibleMcpToolCall,
    McpClient,
    bounded_rss_snapshot,
    bounded_system_failure,
    call_tool,
    classify_websocket_search_outcome_delta,
    enforce_rss_limit,
    read_bounded_diagnostics,
    read_private_token,
    read_project_id,
    sha256_file,
    wait_for_http_call_cleanup,
    wait_for_websocket_search_processing_barrier,
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


def abort_and_delete_active_target(
    active_call: InterruptibleMcpToolCall,
    target: McpClient,
) -> dict[str, Any]:
    if not active_call.abort():
        active_call.join(10)
        raise HarnessError("target read completed before caller socket abort")
    session_delete_status = target.close()
    if session_delete_status not in {200, 202}:
        raise HarnessError("authenticated target session deletion was not accepted")
    active_call.join(10)
    target_outcome = active_call.summary()
    if target_outcome.get("state") != "aborted":
        raise HarnessError("target read returned a response after caller socket abort")
    return {
        "sessionDeleteStatus": session_delete_status,
        "targetOutcome": target_outcome,
    }


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
        "cancellationMechanism": "caller socket abort followed by authenticated session deletion",
        "requestedAttempts": args.attempts,
        "completedBeforeBarrierAttempts": 0,
        "completedAfterTerminationAttempts": 0,
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
        resource_templates = catalog_items(
            observer.rpc("resources/templates/list", {}),
            "resourceTemplates",
        )
        report["catalog"] = validate_catalog(
            args.edition,
            tools,
            prompts,
            resources,
            resource_templates,
            require_v412_schema=requires_v412_catalog_schema(args.expected_server_version),
        )
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

        cancellation_proved = False
        for attempt in range(1, args.attempts + 1):
            outcomes_before = snapshot()
            request_id = 100_000 + attempt
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
                request_id=request_id,
                timeout=180,
            )
            active_call.start()
            try:
                barrier = wait_for_websocket_search_processing_barrier(
                    snapshot,
                    active_call.completed,
                    timeout=args.barrier_timeout_seconds,
                    poll_interval=0.001,
                )
            except HarnessError:
                if active_call.completed.is_set():
                    active_call.join(2)
                    early_summary = active_call.summary()
                    early_outcomes = snapshot()
                    early_delta = classify_websocket_search_outcome_delta(outcomes_before, early_outcomes)
                    if (
                        early_summary.get("state") != "completed"
                        or early_summary.get("httpStatus") != 200
                        or early_summary.get("jsonRpcResponse") is not True
                        or early_delta["outcome"] != "completed"
                    ):
                        raise HarnessError("pre-barrier target attempt did not complete cleanly")
                    report["completedBeforeBarrierAttempts"] += 1
                    active_call = None
                    continue
                active_call.abort()
                active_call.join(10)
                raise

            termination = abort_and_delete_active_target(active_call, target)
            sessions_deleted += 1
            target = None
            target_outcome = termination["targetOutcome"]
            cleanup = wait_for_http_call_cleanup(
                snapshot,
                active_call.completed,
                require_websocket_search_idle=True,
                timeout=10,
                poll_interval=0.01,
            )
            outcomes_after = snapshot()
            outcome_delta = classify_websocket_search_outcome_delta(outcomes_before, outcomes_after)
            active_call = None
            if outcome_delta["outcome"] == "completed":
                report["completedAfterTerminationAttempts"] += 1
                raise HarnessError("target search completed despite the abort-and-delete sequence")

            report["barrierAttempt"] = attempt
            report["activeCallBarrier"] = barrier
            report["socketAbortIssuedAfterBarrier"] = True
            report["targetSessionDeletionAccepted"] = True
            report["targetOutcome"] = target_outcome
            report["cleanupBarrier"] = cleanup
            report["serverCancellationOutcome"] = {
                "cancelledDelta": outcome_delta["cancelledDelta"],
                "completedDelta": outcome_delta["completedDelta"],
            }
            cancellation_proved = True
            break
        if not cancellation_proved:
            raise HarnessError("no target read proved cancellation before bounded search completion")

        if target is not None:
            raise HarnessError("target session remained addressable after the cancellation sequence")
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
