#!/usr/bin/env python3
"""Opt-in 10k/50k/100k loopback WebSocket history diagnostic for a disposable Burp project."""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import secrets
import subprocess
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from exact_smoke_contract import (  # noqa: E402
    EDITION_CATALOG_COUNTS,
    catalog_items,
    validate_catalog,
    validate_release_identity,
)
from live_mcp_harness import (  # noqa: E402
    HarnessError,
    McpClient,
    bounded_rss_snapshot,
    bounded_search_summary,
    bounded_system_failure,
    call_tool,
    enforce_rss_limit,
    read_bounded_diagnostics,
    read_private_token,
    read_project_id,
    run_websocket_fixture,
    sha256_file,
    websocket_search_count,
    write_private_json,
)


def parse_stages(value: str) -> list[int]:
    try:
        stages = [int(item) for item in value.split(",")]
    except ValueError as error:
        raise argparse.ArgumentTypeError("stages must be comma-separated integers") from error
    if stages != sorted(set(stages)) or not stages or any(stage not in {10_000, 50_000, 100_000} for stage in stages):
        raise argparse.ArgumentTypeError("stages must be an ordered subset of 10000,50000,100000")
    return stages


def git_output(root: pathlib.Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=True,
        capture_output=True,
        text=True,
        timeout=15,
    )
    return result.stdout.strip()


def search(client: McpClient, project_id: str, arguments: dict) -> tuple[dict, float]:
    value, elapsed = call_tool(
        client,
        "search_websocket_messages",
        {"projectId": project_id, **arguments},
    )
    if value.get("status") != "ok":
        raise HarnessError("bounded WebSocket search did not complete")
    return value, elapsed


def cursor_checks(client: McpClient, project_id: str) -> dict:
    first, _ = search(client, project_id, {"limit": 1, "newestFirst": True})
    first_items = first.get("items") or []
    cursor = first.get("nextCursor")
    if len(first_items) != 1 or not isinstance(cursor, str) or len(cursor) < 2:
        raise HarnessError("cursor diagnostic could not obtain a first page")
    second, _ = search(client, project_id, {"cursor": cursor, "limit": 1})
    second_items = second.get("items") or []
    first_id = first_items[0].get("id")
    second_id = second_items[0].get("id") if second_items else None
    tampered = ("A" if cursor[0] != "A" else "B") + cursor[1:]
    tampered_value, _ = call_tool(
        client,
        "search_websocket_messages",
        {"projectId": project_id, "cursor": tampered, "limit": 1},
    )
    read_value, _ = call_tool(
        client,
        "get_websocket_message_by_id",
        {"projectId": project_id, "id": first_id, "limit": 64, "encoding": "text"},
    )
    pages_disjoint = bool(first_id and second_id and first_id != second_id)
    if not pages_disjoint or tampered_value.get("status") != "invalid_cursor" or read_value.get("status") != "ok":
        raise HarnessError("cursor or stable-ID diagnostic failed")
    return {
        "pagesDisjoint": pages_disjoint,
        "tamperedCursorStatus": tampered_value.get("status"),
        "stableIdReadStatus": read_value.get("status"),
        "stableIdReadReturnedBytes": read_value.get("returnedBytes"),
        "rawIdentifiersRecorded": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--approved-disposable-project", action="store_true", required=True)
    parser.add_argument("--token-file", required=True, type=pathlib.Path)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument("--candidate-jar", required=True, type=pathlib.Path)
    parser.add_argument("--expected-jar-sha256", required=True)
    parser.add_argument("--expected-source-commit", required=True)
    parser.add_argument("--expected-server-version", required=True)
    parser.add_argument("--endpoint", default="http://127.0.0.1:9876/mcp")
    parser.add_argument("--proxy-port", type=int, default=8080)
    parser.add_argument("--target-port", type=int, default=18765)
    parser.add_argument("--stages", type=parse_stages, default=parse_stages("10000,50000,100000"))
    parser.add_argument("--burp-pid", type=int, required=True)
    parser.add_argument("--max-rss-mib", type=int, default=6144)
    parser.add_argument("--edition", choices=tuple(EDITION_CATALOG_COUNTS), required=True)
    args = parser.parse_args()

    validate_release_identity(
        args.expected_source_commit,
        args.expected_jar_sha256,
        args.expected_server_version,
    )
    if args.max_rss_mib < 1024 or args.max_rss_mib > 32768:
        raise HarnessError("RSS safety limit is outside the accepted range")
    if not args.candidate_jar.is_file() or args.candidate_jar.is_symlink():
        raise HarnessError("candidate JAR must be a regular non-symlink file")
    actual_jar_sha256 = sha256_file(args.candidate_jar)
    if actual_jar_sha256 != args.expected_jar_sha256 or len(actual_jar_sha256) != 64:
        raise HarnessError("candidate JAR checksum does not match")

    source_root = pathlib.Path(__file__).resolve().parent.parent
    source_commit = git_output(source_root, "rev-parse", "--verify", "HEAD")
    if source_commit != args.expected_source_commit or len(source_commit) != 40:
        raise HarnessError("source commit does not match the approved candidate")
    if git_output(source_root, "status", "--porcelain", "--untracked-files=normal"):
        raise HarnessError("live scale diagnostics require a clean source checkout")

    token = read_private_token(args.token_file)
    marker = "independent-scale-" + secrets.token_hex(12)
    max_rss_kib = args.max_rss_mib * 1024
    report: dict = {
        "schemaVersion": 1,
        "status": "failed",
        "edition": args.edition,
        "fixture": "loopback-only deterministic WebSocket echo",
        "sourceCommit": source_commit,
        "candidateJarSha256": actual_jar_sha256,
        "candidateJarName": args.candidate_jar.name,
        "expectedServerVersion": args.expected_server_version,
        "protocol": "2025-11-25",
        "stages": [],
        "latencyClaimMade": False,
        "measurementBoundary": "client wall time and whole Burp process RSS; not a Burp or extension latency benchmark",
        "projectIdentifierRecorded": False,
        "rawTrafficRecorded": False,
    }
    client = McpClient(args.endpoint, token)
    project_id = ""
    failure: str | None = None
    delete_status: int | None = None
    private_session_id = ""
    try:
        initialized = client.initialize()
        private_session_id = client.session_id or ""
        server_info = ((initialized.get("result") or {}).get("serverInfo") or {})
        if (
            server_info.get("name") != "independent-mcp-bridge"
            or server_info.get("version") != args.expected_server_version
        ):
            raise HarnessError("unexpected MCP server identity")
        project_id = read_project_id(client)

        report["catalog"] = validate_catalog(
            args.edition,
            catalog_items(client.rpc("tools/list", {}), "tools"),
            catalog_items(client.rpc("prompts/list", {}), "prompts"),
            catalog_items(client.rpc("resources/list", {}), "resources"),
            catalog_items(
                client.rpc("resources/templates/list", {}),
                "resourceTemplates",
            ),
        )
        diagnostics, diagnostics_text = read_bounded_diagnostics(client)
        if diagnostics.get("loadedArtifactSha256") != actual_jar_sha256:
            raise HarnessError("running extension artifact does not match the approved candidate JAR")
        if any(value and value in diagnostics_text for value in (token, project_id, private_session_id)):
            raise HarnessError("private runtime value reached diagnostics")
        report["loadedArtifactSha256"] = "matched"

        baseline, baseline_elapsed = search(
            client,
            project_id,
            {"limit": 1, "regex": marker + "-absent", "caseSensitive": True, "newestFirst": True},
        )
        baseline_entries = websocket_search_count(baseline, "scanned")
        if baseline.get("scanLimitReached") or baseline_entries >= 10_000:
            raise HarnessError("disposable project baseline is too large for exact staged accounting")
        report["baseline"] = bounded_search_summary(baseline, baseline_elapsed)
        report["baseline"]["estimatedHistoryEntries"] = baseline_entries

        estimated_entries = baseline_entries
        for stage in args.stages:
            delta = stage - estimated_entries
            if delta < 0 or delta % 2:
                raise HarnessError("stage cannot be reached exactly from the observed baseline")
            rss_before = enforce_rss_limit(args.burp_pid, max_rss_kib)
            messages, echoes, fixture_elapsed = run_websocket_fixture(
                message_count=delta // 2,
                marker=marker,
                proxy_port=args.proxy_port,
                target_port=args.target_port,
                safety_check=lambda: enforce_rss_limit(args.burp_pid, max_rss_kib),
            )
            if messages != delta // 2 or echoes != messages:
                raise HarnessError("loopback fixture accounting failed")
            estimated_entries += messages + echoes
            miss, miss_elapsed = search(
                client,
                project_id,
                {"limit": 1, "regex": marker + "-absent", "caseSensitive": True, "newestFirst": True},
            )
            recent, recent_elapsed = search(client, project_id, {"limit": 1, "newestFirst": True})
            rss_after = enforce_rss_limit(args.burp_pid, max_rss_kib)
            stage_observation = {
                "targetHistoryEntries": stage,
                "estimatedHistoryEntriesFromVerifiedFixture": estimated_entries,
                "fixtureMessagesSent": messages,
                "fixtureEchoesReceived": echoes,
                "fixtureClientWallSeconds": round(fixture_elapsed, 6),
                "rssBeforeKiB": rss_before,
                "rssAfterKiB": rss_after,
                "noMatch": bounded_search_summary(miss, miss_elapsed),
                "recentOne": bounded_search_summary(recent, recent_elapsed),
            }
            report["lastObservedStageAttempt"] = stage_observation
            expected_scan = min(estimated_entries, 10_000)
            if websocket_search_count(miss, "scanned") != expected_scan or websocket_search_count(miss, "returned") != 0:
                raise HarnessError("bounded no-match search did not scan the expected limit")
            if websocket_search_count(recent, "returned") != 1 or websocket_search_count(recent, "scanned") != 1:
                raise HarnessError("bounded recent search did not return one record")
            report["stages"].append(stage_observation)
            report.pop("lastObservedStageAttempt", None)

        report["cursorAndStableId"] = cursor_checks(client, project_id)
        report["status"] = "passed"
    except HarnessError as error:
        failure = str(error)
        report["failure"] = failure
    except (OSError, subprocess.SubprocessError) as error:
        failure = bounded_system_failure(error)
        report["failure"] = failure
    finally:
        if client.session_id:
            private_session_id = client.session_id
        try:
            delete_status = client.close()
        except (HarnessError, OSError, subprocess.SubprocessError) as error:
            report["status"] = "failed"
            report["sessionCleanupFailure"] = bounded_system_failure(error)
            report.setdefault("failure", "MCP session cleanup failed")
        report["sessionDeleteHttpStatus"] = delete_status
        final_rss, rss_failure = bounded_rss_snapshot(args.burp_pid, max_rss_kib)
        report["finalRssKiB"] = final_rss
        if rss_failure is not None:
            report["status"] = "failed"
            report["rssObservationFailure"] = rss_failure
            report.setdefault("failure", rss_failure)
        if delete_status not in {200, 202, None} and report["status"] == "passed":
            report["status"] = "failed"
            report["failure"] = "MCP session cleanup failed"
        write_private_json(
            args.output,
            report,
            forbidden_values=tuple(
                value
                for value in (token, project_id, marker, private_session_id, str(pathlib.Path.home()))
                if value
            ),
        )

    print(
        json.dumps(
            {
                "status": report["status"],
                "stagesCompleted": len(report["stages"]),
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
        print(f"live scale diagnostic refused: {type(error).__name__}", file=sys.stderr)
        raise SystemExit(2)
