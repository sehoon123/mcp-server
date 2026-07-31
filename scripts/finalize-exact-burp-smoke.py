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
from live_mcp_harness import HarnessError, read_private_text_file, read_private_token  # noqa: E402


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
    if type(report.get("schemaVersion")) is not int or report.get("schemaVersion") != 1:
        raise HarnessError("edition preflight has an unsupported schema")
    expected = {
        "schemaVersion": 1,
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
    expected_checks = {
        "authenticatedIdentity": "passed",
        "loadedArtifactSha256": "matched",
        "boundedReadOnlyToolCall": "passed",
        "diagnosticsRedaction": "passed",
        "projectBinding": "passed",
        "resourceCatalog": "passed",
        "unauthenticatedStatus401": "passed",
    }
    if checks != expected_checks:
        raise HarnessError("edition preflight checks are incomplete or stale")
    expected_catalog = {
        "counts": expected_counts,
        "identifierSets": "matched",
        "professionalOnlyTools": "absent" if edition == "community" else "present",
        "correlationReadOnly": True,
        "correlationCohortMaxItems": 16,
    }
    if report.get("catalog") != expected_catalog:
        raise HarnessError("edition preflight catalog contract failed")


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def validate_lifecycle_report(
    report: dict[str, Any],
    edition: str,
    source_commit: str,
    jar_sha256: str,
    version: str,
) -> dict[str, bool]:
    expected = {
        "schemaVersion": 1,
        "status": "passed",
        "edition": edition,
        "sourceCommit": source_commit,
        "candidateJarSha256": jar_sha256,
        "serverVersion": version,
        "crossEditionIsolation": {
            "separateInstallationProfile": True,
            "separateDataDirectory": True,
            "separateProject": True,
        },
        "events": [
            {"stage": "initial", "candidateLoaded": True, "authenticated": True},
            {
                "stage": "projectSwitch",
                "differentProjectOpened": True,
                "tokenStable": True,
                "authenticated": True,
            },
            {"stage": "processExit", "fullBurpExit": True, "listenerClosed": True},
            {
                "stage": "processRestart",
                "fullBurpRelaunch": True,
                "sameInstallationProfile": True,
                "tokenStable": True,
                "authenticated": True,
            },
            {
                "stage": "rotationBeforeListenerRestart",
                "explicitUiRotation": True,
                "tokenChanged": True,
                "oldTokenAuthenticated": True,
            },
            {
                "stage": "listenerRestart",
                "listenerRestarted": True,
                "oldTokenRejected401": True,
                "rotatedTokenAuthenticated": True,
            },
            {
                "stage": "secondProcessRestart",
                "fullBurpExit": True,
                "listenerClosed": True,
                "fullBurpRelaunch": True,
                "rotatedTokenStable": True,
                "oldTokenRejected401": True,
                "rotatedTokenAuthenticated": True,
            },
        ],
        "projectIdentifierRecorded": False,
        "sessionIdentifierRecorded": False,
        "bearerRecorded": False,
        "authorizationHeaderRecorded": False,
        "rawTrafficRecorded": False,
        "localPathRecorded": False,
    }
    if canonical_json(report) != canonical_json(expected):
        raise HarnessError(f"{edition} bearer lifecycle report is incomplete, stale, or not candidate-bound")
    return {
        "crossEditionIsolationConfirmed": True,
        "projectSwitchAuthenticated": True,
        "restartAuthenticated": True,
        "listenerStartupTokenRetained": True,
        "rotationCutoverAuthenticated": True,
        "secondRestartStable": True,
    }


def validate_lifecycle_token_files(
    paths: dict[str, dict[str, pathlib.Path]],
) -> tuple[dict[str, dict[str, bool]], list[str]]:
    identities: set[tuple[int, int]] = set()
    values: dict[str, dict[str, str]] = {}
    for edition, stages in paths.items():
        values[edition] = {}
        for stage, path in stages.items():
            value = read_private_token(path)
            metadata = path.stat(follow_symlinks=False)
            identity = (metadata.st_dev, metadata.st_ino)
            if identity in identities:
                raise HarnessError("lifecycle token inputs must be distinct private files")
            identities.add(identity)
            values[edition][stage] = value

    if not set(values["community"].values()).isdisjoint(values["professional"].values()):
        raise HarnessError("Community and Professional lifecycle tokens must be independent")

    summary: dict[str, dict[str, bool]] = {}
    for edition, stages in values.items():
        initial = stages["beforeProjectSwitch"]
        if stages["afterProjectSwitch"] != initial:
            raise HarnessError(f"{edition} local bearer token changed across the project switch")
        if stages["afterRestart"] != initial:
            raise HarnessError(f"{edition} local bearer token changed across the Burp restart")
        if stages["afterRotation"] == initial:
            raise HarnessError(f"{edition} explicit bearer rotation did not change the token")
        summary[edition] = {
            "projectSwitchStable": True,
            "restartStable": True,
            "rotationChanged": True,
        }
    return summary, [value for stages in values.values() for value in stages.values()]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=pathlib.Path)
    parser.add_argument("--community-preflight", required=True)
    parser.add_argument("--professional-preflight", required=True)
    parser.add_argument("--community-lifecycle-report", required=True)
    parser.add_argument("--professional-lifecycle-report", required=True)
    parser.add_argument("--scenario-claims", required=True)
    parser.add_argument("--candidate-jar", required=True)
    parser.add_argument("--expected-jar-sha256", required=True)
    parser.add_argument("--expected-source-commit", required=True)
    parser.add_argument("--expected-server-version", required=True)
    parser.add_argument("--forbidden-value-file", action="append", required=True, type=pathlib.Path)
    for edition in ("community", "professional"):
        parser.add_argument(f"--{edition}-token-before-project-switch", required=True, type=pathlib.Path)
        parser.add_argument(f"--{edition}-token-after-project-switch", required=True, type=pathlib.Path)
        parser.add_argument(f"--{edition}-token-after-restart", required=True, type=pathlib.Path)
        parser.add_argument(f"--{edition}-token-after-rotation", required=True, type=pathlib.Path)
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

    lifecycle_report_relative = (
        args.community_lifecycle_report,
        args.professional_lifecycle_report,
    )
    primary_relative = (
        args.community_preflight,
        args.professional_preflight,
        *lifecycle_report_relative,
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

    opened_file_identities: set[tuple[int, int]] = set()
    jar_sha256 = sha256_below_root(
        args.root,
        args.candidate_jar,
        opened_file_identities=opened_file_identities,
    )
    if jar_sha256 != args.expected_jar_sha256:
        raise HarnessError("candidate JAR checksum does not match")

    primary_snapshots = snapshot_evidence_files(
        args.root,
        primary_relative,
        per_file_max_bytes=4 * 1024 * 1024,
        opened_file_identities=opened_file_identities,
    )
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
    lifecycle_reports = {
        "community": validate_lifecycle_report(
            json_object_from_bytes(primary_snapshots[args.community_lifecycle_report]),
            "community",
            args.expected_source_commit,
            jar_sha256,
            args.expected_server_version,
        ),
        "professional": validate_lifecycle_report(
            json_object_from_bytes(primary_snapshots[args.professional_lifecycle_report]),
            "professional",
            args.expected_source_commit,
            jar_sha256,
            args.expected_server_version,
        ),
    }

    claims_document = json_object_from_bytes(primary_snapshots[args.scenario_claims])
    if (
        set(claims_document) != {"schemaVersion", "scenarios"}
        or type(claims_document.get("schemaVersion")) is not int
        or claims_document.get("schemaVersion") != 1
    ):
        raise HarnessError("scenario claims document has an unsupported schema")
    claims = validate_scenario_claims(claims_document.get("scenarios"))
    scenario_relative = list(dict.fromkeys(
        path
        for claim in claims.values()
        if claim["status"] in {"PASS", "FAIL"}
        for path in claim["evidence"]
    ))
    non_reusable_primary = {
        args.community_preflight,
        args.professional_preflight,
        args.scenario_claims,
    }
    if set(scenario_relative).intersection(non_reusable_primary):
        raise HarnessError("preflight and claims files must not be reused as scenario evidence")
    server_lifecycle_evidence = claims["serverLifecycle"]["evidence"]
    if not all(relative in server_lifecycle_evidence[1:] for relative in lifecycle_report_relative):
        raise HarnessError("serverLifecycle must bind both exact bearer lifecycle reports")
    scenario_snapshots = snapshot_evidence_files(
        args.root,
        [relative for relative in scenario_relative if relative not in primary_snapshots],
        opened_file_identities=opened_file_identities,
    )
    snapshots = {**primary_snapshots, **scenario_snapshots}
    validate_scenario_evidence_snapshots(
        snapshots,
        claims,
        args.expected_source_commit,
        jar_sha256,
        args.expected_server_version,
    )

    lifecycle_paths = {
        edition: {
            "beforeProjectSwitch": getattr(args, f"{edition}_token_before_project_switch"),
            "afterProjectSwitch": getattr(args, f"{edition}_token_after_project_switch"),
            "afterRestart": getattr(args, f"{edition}_token_after_restart"),
            "afterRotation": getattr(args, f"{edition}_token_after_rotation"),
        }
        for edition in ("community", "professional")
    }
    token_lifecycle, lifecycle_tokens = validate_lifecycle_token_files(lifecycle_paths)
    credential_lifecycle = {
        edition: {**token_lifecycle[edition], **lifecycle_reports[edition]}
        for edition in ("community", "professional")
    }
    forbidden_text = [
        read_private_text_file(path, min_chars=1, max_chars=4096)
        for path in args.forbidden_value_file
    ]
    forbidden_text.extend(lifecycle_tokens)
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
        "credentialLifecycle": credential_lifecycle,
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
