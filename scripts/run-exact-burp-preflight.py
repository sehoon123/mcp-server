#!/usr/bin/env python3
"""Verify one exact Burp candidate/edition before scenario-specific smoke work."""

from __future__ import annotations

import argparse
import json
import pathlib
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
    McpClient,
    bounded_rss_snapshot,
    bounded_system_failure,
    call_tool,
    enforce_rss_limit,
    read_bounded_diagnostics,
    read_private_text_file,
    read_private_token,
    read_project_id,
    sha256_file,
    unauthenticated_http_status,
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


def validate_scope_probe(result: Any, project_id: str, target_url: str) -> None:
    if not isinstance(result, dict):
        raise HarnessError("bounded read-only tool call returned a malformed result")
    targets = result.get("targets")
    if not isinstance(targets, list) or len(targets) != 1 or not isinstance(targets[0], dict):
        raise HarnessError("bounded read-only tool call returned malformed targets")
    target = targets[0]
    if (
        result.get("status") != "ok"
        or result.get("projectId") != project_id
        or target.get("index") != 0
        or target.get("url") != target_url
        or type(target.get("inScope")) is not bool
    ):
        raise HarnessError("bounded read-only tool call failed its project-bound result contract")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--approved-disposable-project", action="store_true", required=True)
    parser.add_argument("--edition", choices=tuple(EDITION_CATALOG_COUNTS), required=True)
    parser.add_argument("--token-file", required=True, type=pathlib.Path)
    parser.add_argument("--forbidden-value-file", action="append", default=[], type=pathlib.Path)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument("--candidate-jar", required=True, type=pathlib.Path)
    parser.add_argument("--expected-jar-sha256", required=True)
    parser.add_argument("--expected-source-commit", required=True)
    parser.add_argument("--expected-server-version", required=True)
    parser.add_argument("--endpoint", default="http://127.0.0.1:9876/mcp")
    parser.add_argument("--burp-pid", type=int, required=True)
    parser.add_argument("--max-rss-mib", type=int, default=6144)
    args = parser.parse_args()

    validate_release_identity(
        args.expected_source_commit,
        args.expected_jar_sha256,
        args.expected_server_version,
    )
    if args.max_rss_mib < 1024 or args.max_rss_mib > 32768:
        raise HarnessError("RSS safety limit is outside the accepted range")
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
        raise HarnessError("exact preflight requires a clean source checkout")

    token = read_private_token(args.token_file)
    max_rss_kib = args.max_rss_mib * 1024
    private_values = [
        read_private_text_file(path, min_chars=1, max_chars=4096)
        for path in args.forbidden_value_file
    ]
    private_values.extend((token, str(pathlib.Path.home())))
    project_id = ""
    client = McpClient(args.endpoint, token)
    report: dict[str, Any] = {
        "schemaVersion": 1,
        "status": "failed",
        "edition": args.edition,
        "sourceCommit": source_commit,
        "candidateJarSha256": jar_sha256,
        "candidateJarName": args.candidate_jar.name,
        "expectedServerVersion": args.expected_server_version,
        "protocolVersion": client.protocol,
        "projectIdentifierRecorded": False,
        "sessionIdentifierRecorded": False,
        "bearerRecorded": False,
        "rawTrafficRecorded": False,
        "operatorObservedBurpVersionRecorded": False,
        "rssStartKiB": enforce_rss_limit(args.burp_pid, max_rss_kib),
        "latencyClaimMade": False,
    }
    delete_status: int | None = None
    try:
        if unauthenticated_http_status(args.endpoint) != 401:
            raise HarnessError("unauthenticated MCP probe did not return 401")
        initialized = client.initialize()
        if client.session_id:
            private_values.append(client.session_id)
        server_info = ((initialized.get("result") or {}).get("serverInfo") or {})
        if server_info.get("name") != "independent-mcp-bridge" or server_info.get("version") != args.expected_server_version:
            raise HarnessError("unexpected MCP server identity")
        ping = client.rpc("ping", {})
        if not isinstance(ping, dict) or "result" not in ping:
            raise HarnessError("MCP ping failed")

        tools = catalog_items(client.rpc("tools/list", {}), "tools")
        prompts = catalog_items(client.rpc("prompts/list", {}), "prompts")
        resources = catalog_items(client.rpc("resources/list", {}), "resources")
        resource_templates = catalog_items(
            client.rpc("resources/templates/list", {}),
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

        project_id = read_project_id(client)
        private_values.append(project_id)
        probe_url = "https://example.invalid/"
        result, _ = call_tool(
            client,
            "check_scope",
            {"projectId": project_id, "targets": [{"url": probe_url}]},
            timeout=30,
        )
        validate_scope_probe(result, project_id, probe_url)

        diagnostics, diagnostics_text = read_bounded_diagnostics(client)
        if any(value and value in diagnostics_text for value in private_values):
            raise HarnessError("private runtime value reached diagnostics")
        if diagnostics.get("loadedArtifactSha256") != jar_sha256:
            raise HarnessError("running extension artifact does not match the approved candidate JAR")
        if diagnostics.get("pendingSessions") != 0 or diagnostics.get("activeSessions") != 1:
            raise HarnessError("preflight session state was not bounded")
        if diagnostics.get("activeEventStreams") != 0 or diagnostics.get("sessionsWithApprovals") != 0:
            raise HarnessError("preflight accumulated event stream or approval state")
        report["diagnostics"] = diagnostics
        report["checks"] = {
            "authenticatedIdentity": "passed",
            "loadedArtifactSha256": "matched",
            "boundedReadOnlyToolCall": "passed",
            "diagnosticsRedaction": "passed",
            "projectBinding": "passed",
            "resourceCatalog": "passed",
            "unauthenticatedStatus401": "passed",
        }
        report["status"] = "passed"
    except HarnessError as error:
        report["failure"] = str(error)
    except (OSError, subprocess.SubprocessError) as error:
        report["failure"] = bounded_system_failure(error)
    finally:
        if client.session_id and client.session_id not in private_values:
            private_values.append(client.session_id)
        try:
            delete_status = client.close()
        except (HarnessError, OSError, subprocess.SubprocessError):
            delete_status = None
        report["sessionDeleteAccepted"] = delete_status in {200, 202}
        final_rss, rss_failure = bounded_rss_snapshot(args.burp_pid, max_rss_kib)
        report["rssEndKiB"] = final_rss
        if rss_failure is not None:
            report["status"] = "failed"
            report["rssObservationFailure"] = rss_failure
            report.setdefault("failure", rss_failure)
        if not report["sessionDeleteAccepted"]:
            report["status"] = "failed"
            report.setdefault("failure", "preflight session cleanup failed")
        write_private_json(
            args.output,
            report,
            forbidden_values=tuple(value for value in private_values if value),
        )

    print(
        json.dumps(
            {
                "edition": args.edition,
                "status": report["status"],
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
        print(f"exact Burp preflight refused: {type(error).__name__}", file=sys.stderr)
        raise SystemExit(2)
