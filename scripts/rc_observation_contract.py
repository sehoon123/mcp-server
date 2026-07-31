#!/usr/bin/env python3

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import pathlib
import re
import sys
from typing import Any

MINIMUM_OBSERVATION_SECONDS = 7 * 24 * 60 * 60
MAX_OBSERVED_ISSUES = 1_000
AUTHORIZED_PRIORITY_LABELS = frozenset({"priority:P0", "priority:P1", "priority:P2"})
GATE_LABELS = frozenset({"gate:release-blocker", "gate:non-blocking"})
REQUIRED_LABELS = tuple(sorted(AUTHORIZED_PRIORITY_LABELS | GATE_LABELS))
OBSERVATION_CONTINUITY_PATHS = frozenset(
    {
        ".github/workflows/build.yml",
        ".github/workflows/release-draft.yml",
        ".github/workflows/release-publish.yml",
        ".github/workflows/release-rc-observation.yml",
        "docs/NEXT_RELEASE_ROADMAP.md",
        "docs/RELEASING.md",
        "scripts/rc_observation_contract.py",
        "scripts/test-exact-smoke-contract.py",
        "scripts/test-rc-observation-contract.py",
        "scripts/test-release-vulnerability-gate.py",
    }
)
STABLE_PROMOTION_FIXED_PATHS = frozenset(
    {
        "BappManifest.bmf",
        "docs/VULNERABILITY_REPORT.md",
        "gradle.properties",
    }
)
_RC_TAG = re.compile(
    r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"-rc\.(0|[1-9][0-9]*)(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
_SHA = re.compile(r"^[a-f0-9]{40}$")
_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_TIMESTAMP = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")


class ContractError(ValueError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def _positive_int(value: Any, field: str) -> int:
    _require(type(value) is int and value > 0, f"{field} must be a positive integer")
    return value


def _parse_timestamp(value: Any, field: str) -> dt.datetime:
    _require(isinstance(value, str) and _TIMESTAMP.fullmatch(value) is not None, f"{field} is invalid")
    try:
        return dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)
    except ValueError as error:
        raise ContractError(f"{field} is invalid") from error


def _label_name(value: Any) -> str:
    if isinstance(value, str):
        return value
    _require(isinstance(value, dict), "issue label must be a string or object")
    name = value.get("name")
    _require(isinstance(name, str), "issue label name is invalid")
    return name


def validate_repository(repository_json: Any, repository: str) -> None:
    _require(isinstance(repository_json, dict), "repository metadata must be an object")
    _require(repository_json.get("full_name") == repository, "repository metadata identity mismatch")
    _require(repository_json.get("has_issues") is True, "GitHub Issues must be enabled")
    _require(repository_json.get("archived") is False, "repository must not be archived")
    _require(repository_json.get("disabled") is False, "repository must not be disabled")


def validate_continuity(compare_json: Any, rc_source_commit: str) -> list[str]:
    _require(isinstance(compare_json, dict), "continuity comparison must be an object")
    merge_base = compare_json.get("merge_base_commit")
    _require(isinstance(merge_base, dict), "continuity merge base is missing")
    _require(merge_base.get("sha") == rc_source_commit, "RC source is not the continuity merge base")
    _require(compare_json.get("status") == "ahead", "observation workflow must be ahead of the RC source")
    _require(compare_json.get("behind_by") == 0, "observation workflow is behind the RC source")
    ahead_by = compare_json.get("ahead_by")
    _require(type(ahead_by) is int and ahead_by > 0, "continuity ahead count is invalid")
    files = compare_json.get("files")
    _require(isinstance(files, list) and 1 <= len(files) < 300, "continuity file list is missing or truncated")

    changed: list[str] = []
    for entry in files:
        _require(isinstance(entry, dict), "continuity file entry must be an object")
        filename = entry.get("filename")
        _require(
            isinstance(filename, str) and filename in OBSERVATION_CONTINUITY_PATHS,
            f"runtime or unapproved path changed: {filename}",
        )
        previous = entry.get("previous_filename")
        if previous is not None:
            _require(
                isinstance(previous, str) and previous in OBSERVATION_CONTINUITY_PATHS,
                f"runtime or unapproved path was renamed: {previous}",
            )
        changed.append(filename)
    _require(len(changed) == len(set(changed)), "continuity comparison contains duplicate paths")
    _require(
        set(changed) == OBSERVATION_CONTINUITY_PATHS,
        "observation gate change set does not match the reviewed path set",
    )
    return sorted(changed)


def validate_label_inventory(labels: Any) -> tuple[str, ...]:
    _require(isinstance(labels, list), "label inventory must be an array")
    names: list[str] = []
    for label in labels:
        _require(isinstance(label, dict), "label inventory entry must be an object")
        name = label.get("name")
        _require(isinstance(name, str) and 1 <= len(name) <= 64, "label inventory name is invalid")
        names.append(name)
    _require(len(names) == len(set(names)), "label inventory contains duplicate names")
    missing = set(REQUIRED_LABELS).difference(names)
    _require(not missing, f"required triage labels are missing: {sorted(missing)}")
    return tuple(sorted(names))


def validate_issue_triage(
    issues: Any,
    published_at: dt.datetime,
    observed_at: dt.datetime,
) -> dict[str, Any]:
    _require(isinstance(issues, list), "issues must be an array")

    normalized: list[dict[str, Any]] = []
    seen_numbers: set[int] = set()
    for issue in issues:
        _require(isinstance(issue, dict), "issue entry must be an object")
        if "pull_request" in issue:
            continue
        created_at = _parse_timestamp(issue.get("created_at"), "issue.created_at")
        if created_at < published_at or created_at > observed_at:
            continue
        number = _positive_int(issue.get("number"), "issue.number")
        _require(number not in seen_numbers, "issue query contains duplicate issue numbers")
        seen_numbers.add(number)
        state = issue.get("state")
        _require(state in {"open", "closed"}, "issue.state is invalid")
        labels = issue.get("labels")
        _require(isinstance(labels, list), "issue.labels must be an array")
        label_names = [_label_name(label) for label in labels]
        _require(len(label_names) == len(set(label_names)), "issue contains duplicate labels")
        priority = sorted(AUTHORIZED_PRIORITY_LABELS.intersection(label_names))
        gate = sorted(GATE_LABELS.intersection(label_names))
        _require(len(priority) == 1, f"issue {number} must have exactly one release priority label")
        _require(len(gate) == 1, f"issue {number} must have exactly one release gate disposition")
        normalized.append(
            {
                "number": number,
                "state": state,
                "createdAt": created_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "priority": priority[0],
                "gate": gate[0],
            }
        )

    normalized.sort(key=lambda issue: issue["number"])
    _require(
        len(normalized) <= MAX_OBSERVED_ISSUES,
        "issue query exceeded the bounded observation limit",
    )
    unresolved_p0 = [
        issue["number"]
        for issue in normalized
        if issue["state"] == "open"
        and issue["gate"] == "gate:release-blocker"
        and issue["priority"] == "priority:P0"
    ]
    unresolved_p1 = [
        issue["number"]
        for issue in normalized
        if issue["state"] == "open"
        and issue["gate"] == "gate:release-blocker"
        and issue["priority"] == "priority:P1"
    ]
    _require(not unresolved_p0, f"unresolved release-blocking P0 issues: {unresolved_p0}")
    _require(not unresolved_p1, f"unresolved release-blocking P1 issues: {unresolved_p1}")

    snapshot = json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return {
        "observedIssueCount": len(normalized),
        "triagedIssueNumbers": [issue["number"] for issue in normalized],
        "openReleaseBlockingP0": 0,
        "openReleaseBlockingP1": 0,
        "snapshotSha256": hashlib.sha256(snapshot).hexdigest(),
    }


def validate_global_open_blockers(issues: Any) -> dict[str, Any]:
    _require(isinstance(issues, list), "global open blockers must be an array")
    normalized: list[dict[str, Any]] = []
    seen_numbers: set[int] = set()
    for issue in issues:
        _require(isinstance(issue, dict), "global blocker entry must be an object")
        if "pull_request" in issue:
            continue
        number = _positive_int(issue.get("number"), "global blocker number")
        _require(number not in seen_numbers, "global blocker query contains duplicate issue numbers")
        seen_numbers.add(number)
        _require(issue.get("state") == "open", "global blocker query contains a non-open issue")
        labels = issue.get("labels")
        _require(isinstance(labels, list), "global blocker labels must be an array")
        label_names = [_label_name(label) for label in labels]
        _require(len(label_names) == len(set(label_names)), "global blocker contains duplicate labels")
        priorities = sorted(AUTHORIZED_PRIORITY_LABELS.intersection(label_names))
        gates = sorted(GATE_LABELS.intersection(label_names))
        _require(len(priorities) == 1, f"global blocker {number} must have exactly one priority")
        _require(gates == ["gate:release-blocker"], f"global blocker {number} has an invalid disposition")
        normalized.append({"number": number, "priority": priorities[0]})

    normalized.sort(key=lambda issue: issue["number"])
    _require(
        len(normalized) <= MAX_OBSERVED_ISSUES,
        "global blocker query exceeded the bounded observation limit",
    )
    unresolved_p0 = [issue["number"] for issue in normalized if issue["priority"] == "priority:P0"]
    unresolved_p1 = [issue["number"] for issue in normalized if issue["priority"] == "priority:P1"]
    _require(not unresolved_p0, f"global unresolved release-blocking P0 issues: {unresolved_p0}")
    _require(not unresolved_p1, f"global unresolved release-blocking P1 issues: {unresolved_p1}")
    return {
        "globalOpenBlockerIssueCount": len(normalized),
        "globalOpenBlockerIssueNumbers": [issue["number"] for issue in normalized],
        "globalOpenReleaseBlockingP0": 0,
        "globalOpenReleaseBlockingP1": 0,
    }


def build_observation_record(
    *,
    repository: str,
    rc_tag: str,
    rc_source_commit: str,
    rc_release_id: int,
    rc_jar_sha256: str,
    rc_asset_snapshot_sha256: str,
    rc_published_at: str,
    observed_at: str,
    protected_smoke_run: int,
    publication_run: int,
    observation_workflow_run: int,
    observation_workflow_commit: str,
    observer_actor: str,
    authorized_actor: str,
    repository_json: Any,
    compare_json: Any,
    labels: Any,
    issues: Any,
    open_blockers: Any,
) -> dict[str, Any]:
    _require(_REPOSITORY.fullmatch(repository) is not None, "repository is invalid")
    tag_match = _RC_TAG.fullmatch(rc_tag)
    _require(tag_match is not None, "rc_tag must be a strict vX.Y.Z-rc.N tag")
    base_version = ".".join(tag_match.groups()[:3])
    _require(_SHA.fullmatch(rc_source_commit) is not None, "rc_source_commit is invalid")
    _require(_SHA256.fullmatch(rc_jar_sha256) is not None, "rc_jar_sha256 is invalid")
    _require(_SHA256.fullmatch(rc_asset_snapshot_sha256) is not None, "rc_asset_snapshot_sha256 is invalid")
    _require(_SHA.fullmatch(observation_workflow_commit) is not None, "observation_workflow_commit is invalid")
    _positive_int(rc_release_id, "rc_release_id")
    _positive_int(protected_smoke_run, "protected_smoke_run")
    _positive_int(publication_run, "publication_run")
    _positive_int(observation_workflow_run, "observation_workflow_run")
    _require(
        isinstance(observer_actor, str)
        and observer_actor == authorized_actor
        and 1 <= len(observer_actor) <= 39,
        "observer actor is not authorized",
    )

    published = _parse_timestamp(rc_published_at, "rc_published_at")
    observed = _parse_timestamp(observed_at, "observed_at")
    elapsed_seconds = int((observed - published).total_seconds())
    _require(
        elapsed_seconds >= MINIMUM_OBSERVATION_SECONDS,
        f"RC observation window is only {elapsed_seconds} seconds",
    )
    validate_repository(repository_json, repository)
    changed_paths = validate_continuity(compare_json, rc_source_commit)
    validate_label_inventory(labels)
    issue_triage = validate_issue_triage(issues, published, observed)
    issue_triage.update(validate_global_open_blockers(open_blockers))

    return {
        "schemaVersion": 1,
        "repository": repository,
        "rcTag": rc_tag,
        "baseVersion": base_version,
        "rcSourceCommit": rc_source_commit,
        "rcReleaseId": rc_release_id,
        "rcJarSha256": rc_jar_sha256,
        "rcAssetSnapshotSha256": rc_asset_snapshot_sha256,
        "rcPublishedAt": rc_published_at,
        "observedAt": observed_at,
        "minimumObservationSeconds": MINIMUM_OBSERVATION_SECONDS,
        "elapsedSeconds": elapsed_seconds,
        "protectedSmokeWorkflowRun": protected_smoke_run,
        "publicationWorkflowRun": publication_run,
        "observationWorkflowRun": observation_workflow_run,
        "observationWorkflowCommit": observation_workflow_commit,
        "observerActor": observer_actor,
        "requiredLabels": list(REQUIRED_LABELS),
        "continuityChangedPaths": changed_paths,
        "issueTriage": issue_triage,
        "eligibleForStable": True,
    }


def _load_json(path: pathlib.Path, field: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ContractError(f"{field} is not valid JSON") from error


def _write_new_json(path: pathlib.Path, value: Any) -> None:
    payload = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(payload)


def main() -> int:
    parser = argparse.ArgumentParser(description="Create a bounded seven-day RC observation record")
    parser.add_argument("--repository", required=True)
    parser.add_argument("--rc-tag", required=True)
    parser.add_argument("--rc-source-commit", required=True)
    parser.add_argument("--rc-release-id", required=True, type=int)
    parser.add_argument("--rc-jar-sha256", required=True)
    parser.add_argument("--rc-asset-snapshot-sha256", required=True)
    parser.add_argument("--rc-published-at", required=True)
    parser.add_argument("--observed-at", required=True)
    parser.add_argument("--protected-smoke-run", required=True, type=int)
    parser.add_argument("--publication-run", required=True, type=int)
    parser.add_argument("--observation-workflow-run", required=True, type=int)
    parser.add_argument("--observation-workflow-commit", required=True)
    parser.add_argument("--observer-actor", required=True)
    parser.add_argument("--authorized-actor", required=True)
    parser.add_argument("--repository-json", required=True, type=pathlib.Path)
    parser.add_argument("--compare-json", required=True, type=pathlib.Path)
    parser.add_argument("--labels-json", required=True, type=pathlib.Path)
    parser.add_argument("--issues-json", required=True, type=pathlib.Path)
    parser.add_argument("--open-blockers-json", required=True, type=pathlib.Path)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    arguments = parser.parse_args()

    record = build_observation_record(
        repository=arguments.repository,
        rc_tag=arguments.rc_tag,
        rc_source_commit=arguments.rc_source_commit,
        rc_release_id=arguments.rc_release_id,
        rc_jar_sha256=arguments.rc_jar_sha256,
        rc_asset_snapshot_sha256=arguments.rc_asset_snapshot_sha256,
        rc_published_at=arguments.rc_published_at,
        observed_at=arguments.observed_at,
        protected_smoke_run=arguments.protected_smoke_run,
        publication_run=arguments.publication_run,
        observation_workflow_run=arguments.observation_workflow_run,
        observation_workflow_commit=arguments.observation_workflow_commit,
        observer_actor=arguments.observer_actor,
        authorized_actor=arguments.authorized_actor,
        repository_json=_load_json(arguments.repository_json, "repository_json"),
        compare_json=_load_json(arguments.compare_json, "compare_json"),
        labels=_load_json(arguments.labels_json, "labels_json"),
        issues=_load_json(arguments.issues_json, "issues_json"),
        open_blockers=_load_json(arguments.open_blockers_json, "open_blockers_json"),
    )
    _write_new_json(arguments.output, record)
    print(
        f"RC observation passed: {record['rcTag']} elapsed={record['elapsedSeconds']}s "
        f"issues={record['issueTriage']['observedIssueCount']}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ContractError as error:
        print(f"RC observation failed: {error}", file=sys.stderr)
        raise SystemExit(1)
