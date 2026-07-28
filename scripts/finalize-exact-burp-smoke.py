#!/usr/bin/env python3
"""Build a secret-free exact-byte dual-edition smoke matrix and release disposition."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import subprocess
import sys
from typing import Any

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from exact_smoke_contract import (  # noqa: E402
    EDITION_CATALOG_COUNTS,
    evidence_index_from_snapshots,
    json_object_from_bytes,
    normalize_relative_path,
    protected_workflow_results,
    require_absent_below_root,
    scan_evidence_snapshots,
    sha256_below_root,
    snapshot_evidence_files,
    unlink_below_root,
    scenario_summary,
    validate_permanent_text,
    validate_release_identity,
    validate_scenario_claims,
    validate_scenario_evidence_snapshots,
    write_private_bytes_below_root,
)
from live_mcp_harness import HarnessError, read_private_text_file  # noqa: E402


def git_output(root: pathlib.Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=True,
        capture_output=True,
        text=True,
        timeout=15,
    )
    return result.stdout.strip()


def validate_preflight(
    report: dict[str, Any],
    edition: str,
    source_commit: str,
    jar_sha256: str,
    version: str,
) -> None:
    expected_counts = EDITION_CATALOG_COUNTS[edition]
    expected = {
        "status": "passed",
        "edition": edition,
        "sourceCommit": source_commit,
        "candidateJarSha256": jar_sha256,
        "expectedServerVersion": version,
        "protocolVersion": "2025-11-25",
        "projectIdentifierRecorded": False,
        "sessionIdentifierRecorded": False,
        "bearerRecorded": False,
        "rawTrafficRecorded": False,
        "sessionDeleteAccepted": True,
    }
    for key, value in expected.items():
        if report.get(key) != value:
            raise HarnessError("edition preflight identity or cleanup contract failed")
    checks = report.get("checks")
    if not isinstance(checks, dict) or checks.get("loadedArtifactSha256") != "matched":
        raise HarnessError("edition preflight did not bind the running extension to the candidate JAR")
    catalog = report.get("catalog")
    if not isinstance(catalog, dict) or catalog.get("counts") != expected_counts:
        raise HarnessError("edition preflight catalog contract failed")
    if catalog.get("correlationReadOnly") is not True or catalog.get("correlationCohortMaxItems") != 16:
        raise HarnessError("edition preflight correlation contract failed")
    expected_gating = "absent" if edition == "community" else "present"
    if catalog.get("professionalOnlyTools") != expected_gating:
        raise HarnessError("edition preflight gating contract failed")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=pathlib.Path)
    parser.add_argument("--community-preflight", required=True)
    parser.add_argument("--professional-preflight", required=True)
    parser.add_argument("--scenario-claims", required=True)
    parser.add_argument("--candidate-jar", required=True)
    parser.add_argument("--expected-jar-sha256", required=True)
    parser.add_argument("--expected-source-commit", required=True)
    parser.add_argument("--expected-server-version", required=True)
    parser.add_argument("--forbidden-value-file", action="append", required=True, type=pathlib.Path)
    parser.add_argument("--output", default="SCENARIO_MATRIX.json")
    parser.add_argument("--workflow-results-output")
    parser.add_argument("--require-all-pass", action="store_true")
    args = parser.parse_args()

    validate_release_identity(
        args.expected_source_commit,
        args.expected_jar_sha256,
        args.expected_server_version,
    )
    if args.root.is_symlink() or not args.root.is_dir():
        raise HarnessError("evidence root must be a regular directory")
    source_root = pathlib.Path(__file__).resolve().parent.parent
    if git_output(source_root, "rev-parse", "--verify", "HEAD") != args.expected_source_commit:
        raise HarnessError("source commit does not match the approved candidate")
    if git_output(source_root, "status", "--porcelain", "--untracked-files=normal"):
        raise HarnessError("smoke finalization requires a clean source checkout")

    primary_relative = (
        args.community_preflight,
        args.professional_preflight,
        args.scenario_claims,
    )
    for relative in (*primary_relative, args.candidate_jar, args.output):
        normalize_relative_path(relative)
    if args.workflow_results_output is not None:
        normalize_relative_path(args.workflow_results_output)
        if args.workflow_results_output == args.output:
            raise HarnessError("matrix and workflow results outputs must be different files")
    require_absent_below_root(args.root, args.output)
    if args.workflow_results_output is not None:
        require_absent_below_root(args.root, args.workflow_results_output)

    jar_sha256 = sha256_below_root(args.root, args.candidate_jar)
    if jar_sha256 != args.expected_jar_sha256:
        raise HarnessError("candidate JAR checksum does not match")

    primary_snapshots = snapshot_evidence_files(args.root, primary_relative, per_file_max_bytes=4 * 1024 * 1024)
    community = json_object_from_bytes(primary_snapshots[args.community_preflight])
    professional = json_object_from_bytes(primary_snapshots[args.professional_preflight])
    validate_preflight(
        community,
        "community",
        args.expected_source_commit,
        jar_sha256,
        args.expected_server_version,
    )
    validate_preflight(
        professional,
        "professional",
        args.expected_source_commit,
        jar_sha256,
        args.expected_server_version,
    )

    claims_document = json_object_from_bytes(primary_snapshots[args.scenario_claims])
    if set(claims_document) != {"schemaVersion", "scenarios"} or claims_document.get("schemaVersion") != 1:
        raise HarnessError("scenario claims document has an unsupported schema")
    claims = validate_scenario_claims(claims_document.get("scenarios"))
    scenario_relative = list(dict.fromkeys(
        path
        for claim in claims.values()
        if claim["status"] in {"PASS", "FAIL"}
        for path in claim["evidence"]
    ))
    scenario_snapshots = snapshot_evidence_files(
        args.root,
        [relative for relative in scenario_relative if relative not in primary_snapshots],
    )
    snapshots = {**primary_snapshots, **scenario_snapshots}
    validate_scenario_evidence_snapshots(
        snapshots,
        claims,
        args.expected_source_commit,
        jar_sha256,
        args.expected_server_version,
    )

    forbidden_text = [
        read_private_text_file(path, min_chars=1, max_chars=4096)
        for path in args.forbidden_value_file
    ]
    forbidden_text.append(str(pathlib.Path.home()))
    forbidden = [value.encode("utf-8") for value in forbidden_text]
    scan_evidence_snapshots(snapshots, forbidden)

    summary = scenario_summary(claims)
    matrix: dict[str, Any] = {
        "schemaVersion": 1,
        "candidate": {
            "sourceCommit": args.expected_source_commit,
            "jarSha256": jar_sha256,
            "serverVersion": args.expected_server_version,
            "protocolVersion": "2025-11-25",
        },
        "editions": {
            "community": community["catalog"],
            "professional": professional["catalog"],
        },
        "scenarios": claims,
        "summary": summary,
        "releaseDisposition": "READY_FOR_PROTECTED_SMOKE" if summary["protectedSmokeEligible"] else "WITHHOLD",
        "evidenceSha256": evidence_index_from_snapshots(snapshots),
        "privacy": {
            "forbiddenRuntimeValuesFound": False,
            "privateIdentifierFieldsFound": False,
            "uuidShapedIdentifiersFound": False,
        },
    }
    serialized = (json.dumps(matrix, indent=2, sort_keys=True) + "\n").encode("utf-8")
    validate_permanent_text(serialized, forbidden)
    workflow_results_created = False
    matrix_created = False
    try:
        write_private_bytes_below_root(args.root, args.output, serialized)
        matrix_created = True
        if args.workflow_results_output is not None and summary["protectedSmokeEligible"]:
            workflow_results = protected_workflow_results(
                claims,
                args.expected_server_version,
                evidence_validated=True,
            )
            workflow_serialized = json.dumps(workflow_results, separators=(",", ":"), sort_keys=True).encode("utf-8")
            validate_permanent_text(workflow_serialized, forbidden)
            write_private_bytes_below_root(args.root, args.workflow_results_output, workflow_serialized)
            workflow_results_created = True
    except BaseException:
        if workflow_results_created and args.workflow_results_output is not None:
            unlink_below_root(args.root, args.workflow_results_output)
        if matrix_created:
            unlink_below_root(args.root, args.output)
        raise
    print(
        json.dumps(
            {
                "status": "passed" if summary["protectedSmokeEligible"] else "withheld",
                "summary": summary,
                "outputSha256": hashlib.sha256(serialized).hexdigest(),
                "workflowResultsCreated": workflow_results_created,
            },
            sort_keys=True,
        )
    )
    if args.require_all_pass and not summary["protectedSmokeEligible"]:
        return 1
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (HarnessError, OSError, subprocess.SubprocessError) as error:
        print(f"exact Burp smoke finalization refused: {type(error).__name__}", file=sys.stderr)
        raise SystemExit(2)
