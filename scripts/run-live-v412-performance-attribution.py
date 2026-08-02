#!/usr/bin/env python3
"""Opt-in, aggregate-only live Burp phase attribution for v4.12 related correlation and Scanner delta."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import pathlib
import re
import secrets
import subprocess
import sys
import urllib.parse
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
    diff_history_performance_snapshots,
    enforce_rss_limit,
    parse_history_performance_snapshot,
    read_bounded_diagnostics,
    read_private_json_file,
    read_private_token,
    read_project_id,
    sha256_file,
    validate_loopback_endpoint,
    write_private_json,
)

V412_RC_VERSION = re.compile(r"^4\.12\.0-rc\.[1-9][0-9]*$")
FIXTURE_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
HEX_64 = re.compile(r"^[a-f0-9]{64}$")
HTTP_SOURCES = frozenset({"proxy", "site_map", "organizer"})
RESOLVER_INDEXED_SOURCES = frozenset({"proxy", "organizer"})
STAGES = (10_000, 50_000, 100_000)
RELATED_METRICS = frozenset(
    {
        "RELATED_CORRELATION_MONTOYA_ACQUISITION",
        "RELATED_CORRELATION_EXTENSION_PROCESSING",
    }
)
SCANNER_METRICS = frozenset(
    {
        "SCANNER_DELTA_MONTOYA_ACQUISITION",
        "SCANNER_DELTA_EXTENSION_PROCESSING",
    }
)


def _git_output(root: pathlib.Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=True,
        capture_output=True,
        text=True,
        timeout=15,
    )
    return result.stdout.strip()


def _bounded_integer(value: Any, minimum: int, maximum: int, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value not in range(minimum, maximum + 1):
        raise HarnessError(f"{label} was outside its fixed bound")
    return value


def _bounded_private_string(value: Any, minimum: int, maximum: int, label: str) -> str:
    if (
        not isinstance(value, str)
        or not minimum <= len(value) <= maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise HarnessError(f"{label} was invalid")
    return value


def _validate_reference(value: Any) -> tuple[str, str]:
    if not isinstance(value, dict) or set(value) != {"source", "id"}:
        raise HarnessError("related correlation references were malformed")
    source = value.get("source")
    identifier = value.get("id")
    if source not in HTTP_SOURCES:
        raise HarnessError("related correlation reference source was invalid")
    return source, _bounded_private_string(identifier, 1, 128, "related correlation reference identifier")


def validate_related_arguments(value: dict[str, Any]) -> dict[str, Any]:
    allowed = {"projectId", "baselineRefs", "comparisonRefs", "pathDepth", "relatedTraffic"}
    if set(value) - allowed or not {"projectId", "baselineRefs", "comparisonRefs", "relatedTraffic"}.issubset(value):
        raise HarnessError("related correlation private arguments had unexpected fields")
    _bounded_private_string(value.get("projectId"), 1, 256, "related correlation project binding")
    references: list[tuple[str, str]] = []
    for name in ("baselineRefs", "comparisonRefs"):
        cohort = value.get(name)
        if not isinstance(cohort, list) or not 1 <= len(cohort) <= 16:
            raise HarnessError("related correlation cohort size was invalid")
        references.extend(_validate_reference(item) for item in cohort)
    if len(set(references)) != len(references):
        raise HarnessError("related correlation references were not globally distinct")
    if "pathDepth" in value:
        _bounded_integer(value["pathDepth"], 1, 4, "related correlation path depth")

    related = value.get("relatedTraffic")
    if not isinstance(related, dict) or set(related) - {"seedEventIndices", "sources", "inScopeOnly", "limit"}:
        raise HarnessError("related correlation discovery arguments were malformed")
    seeds = related.get("seedEventIndices")
    if (
        not isinstance(seeds, list)
        or not 1 <= len(seeds) <= 4
        or any(isinstance(item, bool) or not isinstance(item, int) or item not in range(len(references)) for item in seeds)
        or len(set(seeds)) != len(seeds)
    ):
        raise HarnessError("related correlation seed indices were invalid")
    sources = related.get("sources")
    if sources is not None and (
        not isinstance(sources, list)
        or not 1 <= len(sources) <= 3
        or any(source not in HTTP_SOURCES for source in sources)
        or len(set(sources)) != len(sources)
    ):
        raise HarnessError("related correlation discovery sources were invalid")
    if "inScopeOnly" in related and not isinstance(related["inScopeOnly"], bool):
        raise HarnessError("related correlation Scope flag was invalid")
    if "limit" in related:
        _bounded_integer(related["limit"], 1, 16, "related correlation result limit")
    return value


def validate_scanner_arguments(value: dict[str, Any]) -> dict[str, Any]:
    allowed = {
        "count",
        "offset",
        "summariesOnly",
        "cursorMode",
        "sinceSnapshotCursor",
        "severities",
        "confidences",
        "host",
        "nameContains",
        "caseSensitive",
        "newestFirst",
    }
    if set(value) - allowed or "sinceSnapshotCursor" not in value:
        raise HarnessError("Scanner delta private arguments had unexpected fields")
    _bounded_private_string(value.get("sinceSnapshotCursor"), 1, 16_384, "Scanner delta cursor")
    if "count" in value:
        _bounded_integer(value["count"], 1, 50, "Scanner delta count")
    if value.get("offset", 0) != 0 or value.get("summariesOnly") is False:
        raise HarnessError("Scanner delta private arguments requested an unsupported mode")
    for name in ("cursorMode", "summariesOnly", "caseSensitive", "newestFirst"):
        if name in value and not isinstance(value[name], bool):
            raise HarnessError("Scanner delta boolean argument was invalid")
    for name, accepted in (
        ("severities", {"high", "medium", "low", "information", "false_positive"}),
        ("confidences", {"certain", "firm", "tentative"}),
    ):
        values = value.get(name)
        if values is not None and (
            not isinstance(values, list)
            or not 1 <= len(values) <= 8
            or any(item not in accepted for item in values)
            or len(set(values)) != len(values)
        ):
            raise HarnessError(f"Scanner delta {name} were invalid")
    if "host" in value:
        _bounded_private_string(value["host"], 1, 253, "Scanner delta host filter")
    if "nameContains" in value:
        _bounded_private_string(value["nameContains"], 1, 256, "Scanner delta name filter")
    return value


def _related_summary(value: dict[str, Any], arguments: dict[str, Any], project_id: str) -> dict[str, Any]:
    if value.get("status") != "ok" or value.get("projectId") != project_id:
        raise HarnessError("related correlation did not complete in the captured project")
    timeline = value.get("timeline")
    related = value.get("relatedTraffic")
    evidence = value.get("evidence")
    delta = value.get("delta")
    discovery = arguments.get("relatedTraffic")
    if (
        not isinstance(timeline, list)
        or not isinstance(related, dict)
        or not isinstance(evidence, dict)
        or not isinstance(delta, dict)
        or not isinstance(discovery, dict)
    ):
        raise HarnessError("related correlation output was malformed")
    baseline_count = len(arguments["baselineRefs"])
    comparison_count = len(arguments["comparisonRefs"])
    requested_limit = discovery.get("limit", 8)
    returned = _bounded_integer(related.get("returned"), 1, 16, "related returned count")
    query_count = _bounded_integer(related.get("queryCount"), 1, 4, "related query count")
    examined = _bounded_integer(
        related.get("candidateSummariesExamined"),
        1,
        200,
        "related examined summary count",
    )
    qualified = _bounded_integer(related.get("qualifiedCandidates"), 1, 200, "related qualified count")
    matches = related.get("matches")
    expected_cohorts = ["baseline"] * baseline_count + ["comparison"] * comparison_count + ["related"] * returned
    if (
        len(timeline) != baseline_count + comparison_count + returned
        or len(timeline) > 48
        or any(not isinstance(event, dict) for event in timeline)
        or [event.get("cohort") for event in timeline] != expected_cohorts
    ):
        raise HarnessError("related correlation timeline bounds changed")
    source_order = {"proxy": 0, "site_map": 1, "organizer": 2}
    explicit_sources = {reference["source"] for reference in arguments["baselineRefs"] + arguments["comparisonRefs"]}
    expected_sources = discovery.get("sources")
    if expected_sources is None:
        explicit_references = arguments["baselineRefs"] + arguments["comparisonRefs"]
        expected_sources = sorted(
            {explicit_references[index]["source"] for index in discovery["seedEventIndices"]},
            key=source_order.__getitem__,
        )
    else:
        expected_sources = sorted(expected_sources, key=source_order.__getitem__)
    output_sources = related.get("sources")
    related_sources: set[str] = set()
    for event in timeline[baseline_count + comparison_count :]:
        reference = event.get("ref")
        if not isinstance(reference, dict) or reference.get("source") not in HTTP_SOURCES:
            raise HarnessError("related correlation timeline reference was malformed")
        related_sources.add(reference["source"])
    if (
        output_sources != expected_sources
        or related.get("requestedLimit") != requested_limit
        or related.get("seedEventIndices") != discovery.get("seedEventIndices")
        or returned > min(qualified, requested_limit)
        or qualified > examined
        or examined > query_count * 50
        or not isinstance(matches, list)
        or len(matches) != returned
        or not isinstance(related.get("truncated"), bool)
    ):
        raise HarnessError("related correlation discovery accounting changed")
    if returned < min(qualified, requested_limit):
        raise HarnessError("related fixture changed during selected-candidate revalidation")
    if related.get("basis") != "same_service_and_bounded_metadata" or related.get("identityEstablished") is not False:
        raise HarnessError("related correlation interpretation basis changed")
    if evidence.get("ordering") != "caller_supplied_then_related_score":
        raise HarnessError("related correlation ordering basis changed")
    for name in (
        "chronologyEstablished",
        "cohortBoundaryEstablishesTime",
        "exactCrossSourceIdentityEstablished",
        "probableDuplicatesDeduplicated",
    ):
        if evidence.get(name) is not False:
            raise HarnessError("related correlation interpretation limitation changed")
    if (
        evidence.get("selectedReferences") != baseline_count + comparison_count
        or evidence.get("relatedReferences") != returned
        or evidence.get("timelineEvents") != len(timeline)
        or evidence.get("maxReferences") != 32
        or evidence.get("maxReferencesPerCohort") != 16
        or evidence.get("maxRelatedReferences") != 16
        or evidence.get("maxTimelineEvents") != 48
        or delta.get("baselineRecords") != baseline_count
        or delta.get("comparisonRecords") != comparison_count
    ):
        raise HarnessError("related correlation explicit cohort invariants changed")
    selected_processing_attempts = len(related_sources & RESOLVER_INDEXED_SOURCES) + returned + 2
    expected_acquisition_attempts = len(explicit_sources) + query_count * len(expected_sources) + len(related_sources)
    expected_processing_attempts = (
        len(explicit_sources & RESOLVER_INDEXED_SOURCES)
        + baseline_count
        + comparison_count
        + 2 * query_count
        + 7
        + selected_processing_attempts
    )
    return {
        "baselineRecords": baseline_count,
        "comparisonRecords": comparison_count,
        "relatedReturned": returned,
        "timelineEvents": len(timeline),
        "queryCount": query_count,
        "candidateSummariesExamined": examined,
        "qualifiedCandidates": qualified,
        "truncated": related.get("truncated") is True,
        "identityEstablished": False,
        "chronologyEstablished": False,
        "explicitDeltaInputsUnchanged": True,
        "expectedAcquisitionAttemptsPerCall": expected_acquisition_attempts,
        "expectedProcessingAttemptsPerCall": expected_processing_attempts,
    }


def _scanner_summary(value: dict[str, Any], stage: int, project_id: str) -> dict[str, Any]:
    if (
        value.get("status") != "ok"
        or value.get("projectId") != project_id
        or value.get("deltaMode") is not True
        or value.get("legacyMode") is not False
        or value.get("legacyTextTruncated") is not False
        or not isinstance(value.get("scanLimitReached"), bool)
    ):
        raise HarnessError("Scanner delta did not complete in the captured project")
    items = value.get("items")
    delta = value.get("delta")
    if not isinstance(items, list) or not isinstance(delta, dict):
        raise HarnessError("Scanner delta output was malformed")
    returned = _bounded_integer(value.get("returned"), 0, 50, "Scanner delta returned count")
    scanned = _bounded_integer(value.get("scanned"), 1, 10_000, "Scanner delta scanned count")
    if returned != len(items) or returned > scanned or value.get("snapshotSize") != stage:
        raise HarnessError("Scanner delta did not observe the attested exact stage")
    baseline = _bounded_integer(delta.get("baselineSnapshotSize"), 0, stage, "Scanner baseline size")
    current = _bounded_integer(delta.get("currentSnapshotSize"), baseline, stage, "Scanner current size")
    appended = _bounded_integer(delta.get("appendedRangeSize"), 1, stage, "Scanner appended range")
    if current != stage or appended != current - baseline or delta.get("basis") != "append_stable_currently_visible_range":
        raise HarnessError("Scanner delta append-stable basis changed")
    for name in ("regressionEstablished", "removedOrChangedEstablished", "completeHistoryEstablished"):
        if delta.get(name) is not False:
            raise HarnessError("Scanner delta interpretation limitation changed")
    has_more = value.get("hasMore") is True
    next_delta_cursor = value.get("nextDeltaCursor")
    snapshot_cursor = value.get("snapshotCursor")
    if has_more:
        _bounded_private_string(next_delta_cursor, 1, 16_384, "Scanner delta continuation")
        if snapshot_cursor is not None:
            raise HarnessError("Scanner delta advanced its checkpoint before the range was drained")
    else:
        if next_delta_cursor is not None:
            raise HarnessError("Scanner delta continuation contract changed")
        _bounded_private_string(snapshot_cursor, 1, 16_384, "Scanner delta checkpoint")
    return {
        "returned": returned,
        "scanned": scanned,
        "snapshotSize": stage,
        "baselineSnapshotSize": baseline,
        "appendedRangeSize": appended,
        "hasMore": has_more,
        "regressionEstablished": False,
        "removedOrChangedEstablished": False,
        "completeHistoryEstablished": False,
        "expectedAcquisitionAttemptsPerCall": 1,
        "expectedProcessingAttemptsPerCall": 1,
    }


def _attributed_wall_ratio(
    phase_deltas: dict[str, dict[str, int]],
    wall_samples: list[float],
) -> float:
    attributed_nanos = sum(metric["totalNanos"] for metric in phase_deltas.values())
    wall_nanos = sum(wall_samples) * 1_000_000_000
    if wall_nanos <= 0 or attributed_nanos > wall_nanos:
        raise HarnessError("attributed phase time exceeded serial client wall time")
    return round(attributed_nanos / wall_nanos, 9)


def _aggregate_measurement_evidence(
    invariants: dict[str, Any],
    phase_deltas: dict[str, dict[str, int]],
    attributed_wall_ratio: float,
    rss_before: int,
    rss_after: int,
) -> dict[str, Any]:
    """Retain aggregate evidence only; per-call wall measurements remain process-local."""
    return {
        "invariants": invariants,
        "phaseDeltas": phase_deltas,
        "attributedPhaseToClientWallRatio": attributed_wall_ratio,
        "rssBeforeKiB": rss_before,
        "rssAfterKiB": rss_after,
    }


def _catalog_digest(catalogs: dict[str, list[dict[str, Any]]]) -> str:
    normalized = {
        name: sorted(items, key=lambda item: str(item.get("name") or item.get("uri") or item.get("uriTemplate")))
        for name, items in catalogs.items()
    }
    payload = json.dumps(normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _private_strings(value: Any) -> set[str]:
    values: set[str] = set()
    pending = [value]
    while pending:
        current = pending.pop()
        if isinstance(current, dict):
            pending.extend(current.values())
        elif isinstance(current, list):
            pending.extend(current)
        elif isinstance(current, str):
            values.add(current)
    return values


def _assert_report_omits_private_values(report: dict[str, Any], private_values: set[str]) -> None:
    report_strings = _private_strings(report)
    if report_strings.intersection(private_values):
        raise HarnessError("performance report retained a private argument value")


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--approved-disposable-project", action="store_true", required=True)
    parser.add_argument("--operation", choices=("related-correlation", "scanner-delta"), required=True)
    parser.add_argument("--stage", choices=STAGES, required=True, type=int)
    parser.add_argument("--edition", choices=tuple(EDITION_CATALOG_COUNTS), required=True)
    parser.add_argument("--token-file", required=True, type=pathlib.Path)
    parser.add_argument("--arguments-file", required=True, type=pathlib.Path)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument("--candidate-jar", required=True, type=pathlib.Path)
    parser.add_argument("--expected-jar-sha256", required=True)
    parser.add_argument("--expected-source-commit", required=True)
    parser.add_argument("--expected-server-version", required=True)
    parser.add_argument("--fixture-id", required=True)
    parser.add_argument("--fixture-record-sha256", required=True)
    parser.add_argument("--burp-version", required=True)
    parser.add_argument("--jvm-version", required=True)
    parser.add_argument("--os-family", choices=("linux", "macos", "windows"), required=True)
    parser.add_argument("--endpoint", default="http://127.0.0.1:9876/mcp")
    parser.add_argument("--burp-pid", type=int, required=True)
    parser.add_argument("--max-rss-mib", type=int, default=6144)
    parser.add_argument("--warmup-calls", type=int, default=1)
    parser.add_argument("--measured-calls", type=int, default=3)
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    validate_release_identity(args.expected_source_commit, args.expected_jar_sha256, args.expected_server_version)
    if not V412_RC_VERSION.fullmatch(args.expected_server_version):
        raise HarnessError("live v4.12 phase evidence requires an RC candidate identity")
    if not FIXTURE_ID.fullmatch(args.fixture_id) or not HEX_64.fullmatch(args.fixture_record_sha256):
        raise HarnessError("fixture attestation identity was invalid")
    for value, label in ((args.burp_version, "Burp version"), (args.jvm_version, "JVM version")):
        _bounded_private_string(value, 1, 128, label)
    if args.max_rss_mib < 1024 or args.max_rss_mib > 32768:
        raise HarnessError("RSS safety limit is outside the accepted range")
    if args.warmup_calls not in range(1, 4) or args.measured_calls not in range(1, 11):
        raise HarnessError("serial call counts are outside their safety bounds")
    validate_loopback_endpoint(args.endpoint)
    if urllib.parse.urlsplit(args.endpoint).hostname not in {"127.0.0.1", "::1"}:
        raise HarnessError("performance evidence requires a numeric loopback endpoint")
    if args.operation == "scanner-delta" and args.edition != "professional":
        raise HarnessError("Scanner delta performance evidence requires Professional")
    if not args.candidate_jar.is_file() or args.candidate_jar.is_symlink():
        raise HarnessError("candidate JAR must be a regular non-symlink file")
    actual_jar_sha256 = sha256_file(args.candidate_jar)
    if actual_jar_sha256 != args.expected_jar_sha256:
        raise HarnessError("candidate JAR checksum does not match")

    source_root = pathlib.Path(__file__).resolve().parent.parent
    source_commit = _git_output(source_root, "rev-parse", "--verify", "HEAD")
    if source_commit != args.expected_source_commit:
        raise HarnessError("source commit does not match the approved candidate")
    if _git_output(source_root, "status", "--porcelain", "--untracked-files=normal"):
        raise HarnessError("live performance evidence requires a clean source checkout")

    token = read_private_token(args.token_file)
    private_arguments = read_private_json_file(args.arguments_file)
    if args.operation == "related-correlation":
        tool_name = "correlate_http_activity"
        private_arguments = validate_related_arguments(private_arguments)
        expected_metrics = RELATED_METRICS
    else:
        tool_name = "get_scanner_issues"
        private_arguments = validate_scanner_arguments(private_arguments)
        expected_metrics = SCANNER_METRICS
    private_values = _private_strings(private_arguments)
    max_rss_kib = args.max_rss_mib * 1024
    report: dict[str, Any] = {
        "schemaVersion": 1,
        "status": "failed",
        "measurementKind": "live_burp_phase_attribution",
        "runId": secrets.token_hex(12),
        "observedAtUtc": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
        "operation": args.operation,
        "stage": args.stage,
        "edition": args.edition,
        "sourceCommit": source_commit,
        "candidateJarSha256": actual_jar_sha256,
        "serverVersion": args.expected_server_version,
        "burpVersion": args.burp_version,
        "jvmVersion": args.jvm_version,
        "osFamily": args.os_family,
        "runnerSha256": sha256_file(pathlib.Path(__file__).resolve()),
        "fixture": {
            "id": args.fixture_id,
            "recordSha256": args.fixture_record_sha256,
            "sizeEvidence": "observed_snapshot_size" if args.operation == "scanner-delta" else "external_fixture_attestation",
            "disposableProject": True,
        },
        "warmupCalls": args.warmup_calls,
        "measuredCalls": args.measured_calls,
        "rawTrafficRecorded": False,
        "identifiersRecorded": False,
        "filtersRecorded": False,
        "credentialsRecorded": False,
        "localPathsRecorded": False,
        "parallelMontoyaCalls": False,
        "optimizationApplied": False,
        "improvementClaimMade": False,
        "burpProductBenchmarkClaimMade": False,
        "measurementBoundary": (
            "Serial client wall time plus fixed in-process phase totals. Approval waits, project checks, MCP transport, "
            "scheduling, fixture creation, and unrelated Burp background work are not attributed to either phase."
        ),
    }
    client = McpClient(args.endpoint, token)
    private_session_id = ""
    project_id = ""
    delete_status: int | None = None
    try:
        initialized = client.initialize()
        private_session_id = client.session_id or ""
        server_info = ((initialized.get("result") or {}).get("serverInfo") or {})
        if server_info.get("name") != "independent-mcp-bridge" or server_info.get("version") != args.expected_server_version:
            raise HarnessError("unexpected MCP server identity")
        project_id = read_project_id(client)
        if args.operation == "related-correlation" and private_arguments.get("projectId") != project_id:
            raise HarnessError("related correlation arguments belong to a different project")

        catalog_responses = {
            "tools": catalog_items(client.rpc("tools/list", {}), "tools"),
            "prompts": catalog_items(client.rpc("prompts/list", {}), "prompts"),
            "resources": catalog_items(client.rpc("resources/list", {}), "resources"),
            "resourceTemplates": catalog_items(
                client.rpc("resources/templates/list", {}),
                "resourceTemplates",
            ),
        }
        report["catalog"] = validate_catalog(
            args.edition,
            catalog_responses["tools"],
            catalog_responses["prompts"],
            catalog_responses["resources"],
            catalog_responses["resourceTemplates"],
            require_v412_schema=requires_v412_catalog_schema(args.expected_server_version),
        )
        report["catalog"]["canonicalSha256"] = _catalog_digest(catalog_responses)

        diagnostics, diagnostics_text = read_bounded_diagnostics(client)
        if diagnostics.get("loadedArtifactSha256") != actual_jar_sha256:
            raise HarnessError("running extension artifact does not match the candidate JAR")
        if any(value and value in diagnostics_text for value in (token, project_id, private_session_id)):
            raise HarnessError("private runtime value reached diagnostics")

        warmup_summary: dict[str, Any] | None = None
        for _ in range(args.warmup_calls):
            value, _ = call_tool(client, tool_name, private_arguments)
            summary = (
                _related_summary(value, private_arguments, project_id)
                if args.operation == "related-correlation"
                else _scanner_summary(value, args.stage, project_id)
            )
            if warmup_summary is not None and summary != warmup_summary:
                raise HarnessError("warmup result invariants were not stable")
            warmup_summary = summary

        _, before_text = read_bounded_diagnostics(client)
        before = parse_history_performance_snapshot(before_text)
        rss_before = enforce_rss_limit(args.burp_pid, max_rss_kib)
        wall_measurements: list[float] = []
        measured_summary: dict[str, Any] | None = None
        for _ in range(args.measured_calls):
            enforce_rss_limit(args.burp_pid, max_rss_kib)
            value, elapsed = call_tool(client, tool_name, private_arguments)
            summary = (
                _related_summary(value, private_arguments, project_id)
                if args.operation == "related-correlation"
                else _scanner_summary(value, args.stage, project_id)
            )
            if measured_summary is not None and summary != measured_summary:
                raise HarnessError("measured result invariants were not stable")
            measured_summary = summary
            wall_measurements.append(elapsed)

        rss_after = enforce_rss_limit(args.burp_pid, max_rss_kib)
        _, after_text = read_bounded_diagnostics(client)
        after = parse_history_performance_snapshot(after_text)
        phase_deltas = diff_history_performance_snapshots(before, after, expected_metrics)
        if any(
            metric["completed"] != metric["attempts"] or metric["failed"] or metric["cancelled"]
            for metric in phase_deltas.values()
        ):
            raise HarnessError("phase attribution included a failed or cancelled segment")
        expected_attempts = {
            (
                "RELATED_CORRELATION_MONTOYA_ACQUISITION"
                if args.operation == "related-correlation"
                else "SCANNER_DELTA_MONTOYA_ACQUISITION"
            ): measured_summary["expectedAcquisitionAttemptsPerCall"] * args.measured_calls,
            (
                "RELATED_CORRELATION_EXTENSION_PROCESSING"
                if args.operation == "related-correlation"
                else "SCANNER_DELTA_EXTENSION_PROCESSING"
            ): measured_summary["expectedProcessingAttemptsPerCall"] * args.measured_calls,
        }
        if any(phase_deltas[name]["attempts"] != attempts for name, attempts in expected_attempts.items()):
            raise HarnessError("phase attribution attempt cardinality changed or was contaminated")
        attributed_wall_ratio = _attributed_wall_ratio(phase_deltas, wall_measurements)

        report.update(
            _aggregate_measurement_evidence(
                measured_summary,
                phase_deltas,
                attributed_wall_ratio,
                rss_before,
                rss_after,
            )
        )
        report["loadedArtifactSha256Matched"] = True
        report["status"] = "passed"
    except HarnessError as error:
        report["failure"] = str(error)[:256]
    except (OSError, subprocess.SubprocessError) as error:
        report["failure"] = bounded_system_failure(error)
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

        _assert_report_omits_private_values(report, private_values | {token, project_id, private_session_id, args.endpoint})
        forbidden_substrings = tuple(
            value
            for value in (token, project_id, private_session_id, args.endpoint, str(pathlib.Path.home()))
            if value
        ) + tuple(value for value in private_values if len(value) >= 8)
        write_private_json(args.output, report, forbidden_values=forbidden_substrings)

    print(
        json.dumps(
            {
                "status": report["status"],
                "operation": args.operation,
                "stage": args.stage,
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
        print(f"live v4.12 performance attribution refused: {type(error).__name__}", file=sys.stderr)
        raise SystemExit(2)
