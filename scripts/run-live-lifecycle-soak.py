#!/usr/bin/env python3
"""Opt-in bounded MCP session lifecycle soak against a disposable loopback Burp project."""

from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from live_mcp_harness import (  # noqa: E402
    HarnessError,
    McpClient,
    SUPPORTED_PROTOCOLS,
    bounded_rss_snapshot,
    bounded_system_failure,
    call_tool,
    current_rss_kib,
    enforce_rss_limit,
    read_private_token,
    read_project_id,
    sha256_file,
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


def read_diagnostics(client: McpClient) -> dict:
    response = client.rpc("resources/read", {"uri": "burp://diagnostics"})
    try:
        text = response["result"]["contents"][0]["text"]
        value = json.loads(text)["diagnostics"]
    except (KeyError, IndexError, TypeError, json.JSONDecodeError):
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
    }
    return {key: value.get(key) for key in sorted(allowed)}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--approved-disposable-project", action="store_true", required=True)
    parser.add_argument("--token-file", required=True, type=pathlib.Path)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument("--candidate-jar", required=True, type=pathlib.Path)
    parser.add_argument("--expected-jar-sha256", required=True)
    parser.add_argument("--expected-source-commit", required=True)
    parser.add_argument("--endpoint", default="http://127.0.0.1:9876/mcp")
    parser.add_argument("--duration-seconds", type=int, default=1800)
    parser.add_argument("--interval-seconds", type=float, default=1.0)
    parser.add_argument("--burp-pid", type=int, required=True)
    parser.add_argument("--max-rss-mib", type=int, default=6144)
    parser.add_argument("--expected-tools", type=int, choices=(24, 31), required=True)
    parser.add_argument("--expected-prompts", type=int, choices=(4, 5), required=True)
    args = parser.parse_args()

    if args.duration_seconds not in range(60, 28_801):
        raise HarnessError("soak duration must be between one minute and eight hours")
    if not 0 <= args.interval_seconds <= 60:
        raise HarnessError("soak interval is outside its safety bound")
    if args.max_rss_mib < 1024 or args.max_rss_mib > 32768:
        raise HarnessError("RSS safety limit is outside the accepted range")
    if not args.candidate_jar.is_file() or args.candidate_jar.is_symlink():
        raise HarnessError("candidate JAR must be a regular non-symlink file")
    jar_sha256 = sha256_file(args.candidate_jar)
    if jar_sha256 != args.expected_jar_sha256:
        raise HarnessError("candidate JAR checksum does not match")

    source_root = pathlib.Path(__file__).resolve().parent.parent
    source_commit = git_output(source_root, "rev-parse", "--verify", "HEAD")
    if source_commit != args.expected_source_commit:
        raise HarnessError("source commit does not match the approved candidate")
    if git_output(source_root, "status", "--porcelain", "--untracked-files=normal"):
        raise HarnessError("lifecycle soak requires a clean source checkout")

    token = read_private_token(args.token_file)
    max_rss_kib = args.max_rss_mib * 1024
    report: dict = {
        "schemaVersion": 1,
        "status": "failed",
        "fixture": "loopback-only existing disposable history",
        "sourceCommit": source_commit,
        "candidateJarSha256": jar_sha256,
        "candidateJarName": args.candidate_jar.name,
        "requestedDurationSeconds": args.duration_seconds,
        "protocols": list(SUPPORTED_PROTOCOLS),
        "cyclesByProtocol": {protocol: 0 for protocol in SUPPORTED_PROTOCOLS},
        "completedCycles": 0,
        "successfulInitializations": 0,
        "sessionsCreated": 0,
        "sessionDeletesAccepted": 0,
        "maxCycleClientWallSeconds": 0.0,
        "rssStartKiB": enforce_rss_limit(args.burp_pid, max_rss_kib),
        "rssMaxKiB": current_rss_kib(args.burp_pid),
        "transportStatePlateauObserved": True,
        "projectIdentifierRecorded": False,
        "rawTrafficRecorded": False,
        "latencyClaimMade": False,
        "limitations": [
            "This bounded run does not automate Burp restart, project replacement, or extension unload/reload.",
            "Client wall time and whole-process RSS are diagnostic only.",
        ],
    }
    project_id = ""
    deadline = time.monotonic() + args.duration_seconds
    cycle = 0
    try:
        while time.monotonic() < deadline:
            cycle_started = time.perf_counter()
            protocol = SUPPORTED_PROTOCOLS[cycle % len(SUPPORTED_PROTOCOLS)]
            client = McpClient(args.endpoint, token, protocol)
            delete_status: int | None = None
            delete_failure: str | None = None
            try:
                initialized = client.initialize()
                report["successfulInitializations"] += 1
                server_info = ((initialized.get("result") or {}).get("serverInfo") or {})
                if server_info.get("name") != "independent-mcp-bridge" or server_info.get("version") != "4.10.0-dev.1":
                    raise HarnessError("unexpected MCP server identity")
                project_id = read_project_id(client)
                if cycle < len(SUPPORTED_PROTOCOLS):
                    tools = client.rpc("tools/list", {})
                    prompts = client.rpc("prompts/list", {})
                    resources = client.rpc("resources/list", {})
                    if len(((tools.get("result") or {}).get("tools") or [])) != args.expected_tools:
                        raise HarnessError("tool catalog changed during soak")
                    if len(((prompts.get("result") or {}).get("prompts") or [])) != args.expected_prompts:
                        raise HarnessError("prompt catalog changed during soak")
                    if len(((resources.get("result") or {}).get("resources") or [])) != 3:
                        raise HarnessError("resource catalog changed during soak")

                search, _ = call_tool(
                    client,
                    "search_websocket_messages",
                    {"projectId": project_id, "limit": 1, "newestFirst": True},
                )
                if (
                    search.get("status") != "ok"
                    or websocket_search_count(search, "returned") not in {0, 1}
                    or websocket_search_count(search, "scanned") not in {0, 1}
                ):
                    raise HarnessError("bounded WebSocket search failed during soak")
                diagnostics = read_diagnostics(client)
                if diagnostics.get("pendingSessions") != 0 or diagnostics.get("activeSessions") != 1:
                    report["transportStatePlateauObserved"] = False
                    raise HarnessError("session state did not return to its single-cycle plateau")
                if diagnostics.get("activeEventStreams") != 0 or diagnostics.get("sessionsWithApprovals") != 0:
                    report["transportStatePlateauObserved"] = False
                    raise HarnessError("event stream or approval state accumulated during soak")
            finally:
                session_was_created = client.session_id is not None
                try:
                    delete_status = client.close()
                except (HarnessError, OSError, subprocess.SubprocessError) as error:
                    delete_failure = bounded_system_failure(error)
                    report["sessionCleanupFailure"] = delete_failure
                if session_was_created:
                    report["sessionsCreated"] += 1
                if delete_status in {200, 202}:
                    report["sessionDeletesAccepted"] += 1
            if delete_failure is not None:
                raise HarnessError("MCP session cleanup failed during soak")
            if delete_status not in {200, 202}:
                raise HarnessError("session DELETE failed during soak")

            rss = enforce_rss_limit(args.burp_pid, max_rss_kib)
            if rss is not None:
                previous = report["rssMaxKiB"]
                report["rssMaxKiB"] = rss if previous is None else max(previous, rss)
            elapsed = time.perf_counter() - cycle_started
            report["maxCycleClientWallSeconds"] = max(report["maxCycleClientWallSeconds"], round(elapsed, 6))
            report["completedCycles"] += 1
            report["cyclesByProtocol"][protocol] += 1
            cycle += 1
            remaining = deadline - time.monotonic()
            if remaining > 0 and args.interval_seconds:
                time.sleep(min(args.interval_seconds, remaining))

        report["status"] = "passed"
    except HarnessError as error:
        report["failure"] = str(error)
    except (OSError, subprocess.SubprocessError) as error:
        report["failure"] = bounded_system_failure(error)
    finally:
        report["actualDurationSeconds"] = round(args.duration_seconds - max(deadline - time.monotonic(), 0), 3)
        final_rss, rss_failure = bounded_rss_snapshot(args.burp_pid, max_rss_kib)
        report["rssEndKiB"] = final_rss
        if rss_failure is not None:
            report["status"] = "failed"
            report["rssObservationFailure"] = rss_failure
            report.setdefault("failure", rss_failure)
        report["allCreatedSessionsDeleted"] = (
            report["sessionsCreated"] == report["sessionDeletesAccepted"]
        )
        if not report["allCreatedSessionsDeleted"] and report["status"] == "passed":
            report["status"] = "failed"
            report["failure"] = "not every created session was deleted"
        write_private_json(
            args.output,
            report,
            forbidden_values=tuple(value for value in (token, project_id, str(pathlib.Path.home())) if value),
        )

    print(
        json.dumps(
            {
                "status": report["status"],
                "completedCycles": report["completedCycles"],
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
        print(f"lifecycle soak refused: {type(error).__name__}", file=sys.stderr)
        raise SystemExit(2)
