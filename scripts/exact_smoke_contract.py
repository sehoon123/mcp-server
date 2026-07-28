#!/usr/bin/env python3
"""Pure validation contracts for exact-byte Burp smoke evidence."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import stat
from typing import Any, Iterable

from live_mcp_harness import HarnessError, read_bounded_regular_file, sha256_file

EDITION_CATALOG_COUNTS = {
    "community": {"tools": 25, "prompts": 4, "resources": 3},
    "professional": {"tools": 32, "prompts": 5, "resources": 3},
}
PROFESSIONAL_ONLY_TOOLS = frozenset(
    {
        "get_scanner_issues",
        "search_scanner_issues",
        "start_scanner_audit",
        "get_scanner_audit_status",
        "cancel_scanner_audit",
        "generate_collaborator_payload",
        "poll_collaborator_interactions",
    }
)
SMOKE_SCENARIO_KEYS = frozenset(
    {
        "boundedLargeDataAndCancellation",
        "catalogEditionGating",
        "dataApprovalAndProjectTransition",
        "diagnosticsRedaction",
        "embeddedStdio",
        "loadUnload",
        "nativeHttp",
        "professionalScannerCollaborator",
        "routingNoHiddenNetwork",
        "scopeScannerUncertainOutcomes",
        "serverLifecycle",
        "stableIdReplayIndependentApprovals",
        "unloadDuringBackgroundWork",
    }
)
SMOKE_STATUSES = ("PASS", "FAIL", "BLOCKED", "NOT RUN")
SCENARIO_REQUIRED_EDITIONS = {
    key: ("professional",)
    if key in {"professionalScannerCollaborator", "scopeScannerUncertainOutcomes"}
    else ("community", "professional")
    for key in SMOKE_SCENARIO_KEYS
}
_HEX_40 = re.compile(r"^[a-f0-9]{40}$")
_HEX_64 = re.compile(r"^[a-f0-9]{64}$")
_UUID_VALUE = re.compile(rb"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b")
_PRIVATE_JSON_FIELD = re.compile(
    rb'(?i)"(?:projectId|sessionId|stableId|scannerTaskId|collaboratorPayload)"\s*:'
)
_CREDENTIAL_FIELD = re.compile(
    rb'(?im)(?:^|[\r\n{,])\s*"?(?:authorization|proxy-authorization|cookie|set-cookie)"?\s*:'
)
_PRIVATE_JSON_KEYS = frozenset({"projectid", "sessionid", "stableid", "scannertaskid", "collaboratorpayload"})
_CREDENTIAL_JSON_KEYS = frozenset({"authorization", "proxy-authorization", "cookie", "set-cookie"})


def validate_release_identity(source_commit: str, jar_sha256: str, version: str) -> None:
    if not _HEX_40.fullmatch(source_commit):
        raise HarnessError("source commit must be 40 lowercase hexadecimal characters")
    if not _HEX_64.fullmatch(jar_sha256):
        raise HarnessError("JAR SHA-256 must be 64 lowercase hexadecimal characters")
    if not version or len(version) > 128 or any(ord(character) < 32 for character in version):
        raise HarnessError("server version is invalid")


def validate_catalog(
    edition: str,
    tools: list[dict[str, Any]],
    prompts: list[dict[str, Any]],
    resources: list[dict[str, Any]],
) -> dict[str, Any]:
    expected = EDITION_CATALOG_COUNTS.get(edition)
    if expected is None:
        raise HarnessError("edition must be community or professional")
    if not all(isinstance(value, list) for value in (tools, prompts, resources)):
        raise HarnessError("MCP catalogs were not arrays")
    counts = {"tools": len(tools), "prompts": len(prompts), "resources": len(resources)}
    if counts != expected:
        raise HarnessError("catalog counts do not match the approved edition")
    tool_names = [tool.get("name") for tool in tools]
    if any(not isinstance(name, str) or not name for name in tool_names) or len(set(tool_names)) != len(tool_names):
        raise HarnessError("tool catalog contains invalid or duplicate names")
    professional_present = sorted(PROFESSIONAL_ONLY_TOOLS.intersection(tool_names))
    if edition == "community" and professional_present:
        raise HarnessError("Community catalog exposed Professional-only tools")
    if edition == "professional" and professional_present != sorted(PROFESSIONAL_ONLY_TOOLS):
        raise HarnessError("Professional catalog omitted Professional-only tools")

    correlation = next((tool for tool in tools if tool.get("name") == "correlate_http_activity"), None)
    if correlation is None:
        raise HarnessError("correlation tool is absent")
    annotations = correlation.get("annotations") or {}
    properties = (correlation.get("inputSchema") or {}).get("properties") or {}
    if annotations.get("readOnlyHint") is not True or annotations.get("destructiveHint") is not False:
        raise HarnessError("correlation tool annotations changed")
    for name in ("baselineRefs", "comparisonRefs"):
        if (properties.get(name) or {}).get("maxItems") != 16:
            raise HarnessError("correlation cohort bounds changed")

    return {
        "counts": counts,
        "professionalOnlyTools": "absent" if edition == "community" else "present",
        "correlationReadOnly": True,
        "correlationCohortMaxItems": 16,
    }


def validate_scenario_claims(value: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(value, dict) or set(value) != SMOKE_SCENARIO_KEYS:
        raise HarnessError("scenario claims must contain exactly the protected smoke keys")
    normalized: dict[str, dict[str, Any]] = {}
    for key in sorted(SMOKE_SCENARIO_KEYS):
        claim = value.get(key)
        if not isinstance(claim, dict) or set(claim) != {"status", "evidence", "notes"}:
            raise HarnessError("each scenario claim must contain status, evidence, and notes")
        status = claim.get("status")
        evidence = claim.get("evidence")
        notes = claim.get("notes")
        if status not in SMOKE_STATUSES:
            raise HarnessError("scenario status is invalid")
        if not isinstance(evidence, list) or len(evidence) > 32 or any(not isinstance(item, str) for item in evidence):
            raise HarnessError("scenario evidence list is invalid")
        if len(set(evidence)) != len(evidence):
            raise HarnessError("scenario evidence list contains duplicates")
        if status in {"PASS", "FAIL"} and not evidence:
            raise HarnessError("PASS and FAIL scenario claims require evidence")
        if not isinstance(notes, str) or not 1 <= len(notes) <= 2048 or any(ord(character) < 32 and character not in "\t\n" for character in notes):
            raise HarnessError("scenario notes are invalid")
        validate_permanent_text(notes.encode("utf-8"), ())
        normalized[key] = {"status": status, "evidence": list(evidence), "notes": notes}
    return normalized


def validate_scenario_evidence_snapshots(
    snapshots: dict[str, bytes],
    claims: dict[str, dict[str, Any]],
    source_commit: str,
    jar_sha256: str,
    version: str,
) -> None:
    record_paths: set[str] = set()
    objective_paths: set[str] = set()
    for key, claim in claims.items():
        if claim["status"] not in {"PASS", "FAIL"}:
            continue
        evidence = claim["evidence"]
        if len(evidence) < 2 or not evidence[0].endswith(".json"):
            raise HarnessError("PASS and FAIL claims require a unique scenario record plus objective evidence")
        record_relative = evidence[0]
        if record_relative in record_paths:
            raise HarnessError("scenario records must not be shared across scenarios")
        record_paths.add(record_relative)
        if any(path not in snapshots for path in evidence):
            raise HarnessError("scenario evidence snapshot is incomplete")
        record = json_object_from_bytes(snapshots[record_relative])
        expected_keys = {
            "schemaVersion",
            "scenario",
            "status",
            "sourceCommit",
            "candidateJarSha256",
            "serverVersion",
            "editions",
            "checks",
        }
        if set(record) != expected_keys or record.get("schemaVersion") != 1:
            raise HarnessError("scenario evidence record has an unsupported schema")
        if (
            record.get("scenario") != key
            or record.get("status") != claim["status"]
            or record.get("sourceCommit") != source_commit
            or record.get("candidateJarSha256") != jar_sha256
            or record.get("serverVersion") != version
        ):
            raise HarnessError("scenario evidence record is not bound to the candidate and claim")
        editions = record.get("editions")
        if editions != list(SCENARIO_REQUIRED_EDITIONS[key]):
            raise HarnessError("scenario evidence record does not cover its required editions")
        checks = record.get("checks")
        if not isinstance(checks, list) or not 1 <= len(checks) <= 31:
            raise HarnessError("scenario evidence record checks are invalid")
        checked_paths: list[str] = []
        results: list[str] = []
        for check in checks:
            if not isinstance(check, dict) or set(check) != {"name", "path", "sha256", "result"}:
                raise HarnessError("scenario evidence check has an unsupported schema")
            name = check.get("name")
            path = check.get("path")
            digest = check.get("sha256")
            result = check.get("result")
            if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", name):
                raise HarnessError("scenario evidence check name is invalid")
            if not isinstance(path, str) or path == record_relative:
                raise HarnessError("scenario evidence check path is invalid")
            if not isinstance(digest, str) or not _HEX_64.fullmatch(digest):
                raise HarnessError("scenario evidence check digest is invalid")
            if result not in {"pass", "fail"}:
                raise HarnessError("scenario evidence check result is invalid")
            checked_paths.append(path)
            results.append(result)
        if len(set(checked_paths)) != len(checked_paths) or checked_paths != evidence[1:]:
            raise HarnessError("scenario record checks must bind every claimed objective evidence file in order")
        if objective_paths.intersection(checked_paths):
            raise HarnessError("objective evidence files must not be shared across scenarios")
        objective_paths.update(checked_paths)
        for check, path in zip(checks, evidence[1:]):
            if hashlib.sha256(snapshots[path]).hexdigest() != check["sha256"]:
                raise HarnessError("scenario objective evidence digest does not match its record")
        if claim["status"] == "PASS" and any(result != "pass" for result in results):
            raise HarnessError("PASS scenario record contains a non-pass objective check")
        if claim["status"] == "FAIL" and "fail" not in results:
            raise HarnessError("FAIL scenario record contains no failed objective check")


def validate_scenario_evidence_records(
    root: pathlib.Path,
    claims: dict[str, dict[str, Any]],
    source_commit: str,
    jar_sha256: str,
    version: str,
) -> list[pathlib.Path]:
    relative_paths = list(dict.fromkeys(
        path
        for claim in claims.values()
        if claim["status"] in {"PASS", "FAIL"}
        for path in claim["evidence"]
    ))
    snapshots = snapshot_evidence_files(root, relative_paths)
    validate_scenario_evidence_snapshots(snapshots, claims, source_commit, jar_sha256, version)
    return [root.joinpath(*pathlib.PurePosixPath(path).parts) for path in relative_paths]


def resolve_evidence_paths(root: pathlib.Path, relative_paths: Iterable[str]) -> list[pathlib.Path]:
    if root.is_symlink() or not root.is_dir():
        raise HarnessError("evidence root must be a regular directory")
    resolved_root = root.resolve()
    output: list[pathlib.Path] = []
    for relative in relative_paths:
        candidate_relative = pathlib.PurePosixPath(relative)
        if candidate_relative.is_absolute() or ".." in candidate_relative.parts or not candidate_relative.parts:
            raise HarnessError("evidence path must stay below the evidence root")
        candidate = root
        for part in candidate_relative.parts:
            candidate = candidate / part
            if candidate.is_symlink():
                raise HarnessError("evidence path must not contain symlink components")
        if not candidate.is_file():
            raise HarnessError("evidence path must name a regular non-symlink file")
        resolved = candidate.resolve()
        if resolved_root not in resolved.parents:
            raise HarnessError("evidence path escaped the evidence root")
        output.append(candidate)
    return output


def _validate_json_privacy(value: Any, forbidden_text: tuple[str, ...]) -> None:
    stack = [value]
    visited = 0
    while stack:
        visited += 1
        if visited > 1_000_000:
            raise HarnessError("JSON evidence exceeded its structural safety bound")
        current = stack.pop()
        if isinstance(current, dict):
            for key, nested in current.items():
                if isinstance(key, str):
                    normalized = key.casefold()
                    if normalized in _CREDENTIAL_JSON_KEYS:
                        raise HarnessError("credential-bearing field reached permanent smoke evidence")
                    if normalized in _PRIVATE_JSON_KEYS:
                        raise HarnessError("private identifier field reached permanent smoke evidence")
                stack.append(nested)
        elif isinstance(current, list):
            stack.extend(current)
        elif isinstance(current, str):
            encoded = current.encode("utf-8")
            if any(forbidden and forbidden in current for forbidden in forbidden_text):
                raise HarnessError("private runtime value reached permanent smoke evidence")
            if _UUID_VALUE.search(encoded):
                raise HarnessError("UUID-shaped private identifier reached permanent smoke evidence")
            if _CREDENTIAL_FIELD.search(encoded):
                raise HarnessError("credential-bearing field reached permanent smoke evidence")


def normalize_relative_path(relative: str) -> tuple[str, ...]:
    if not isinstance(relative, str) or "\\" in relative or any(ord(character) < 32 for character in relative):
        raise HarnessError("evidence path contains unsupported characters")
    candidate = pathlib.PurePosixPath(relative)
    if candidate.is_absolute() or ".." in candidate.parts or not candidate.parts:
        raise HarnessError("evidence path must stay below the evidence root")
    return candidate.parts


def _open_parent_below_root(root: pathlib.Path, relative: str) -> tuple[int, str]:
    if os.open not in os.supports_dir_fd or os.stat not in os.supports_dir_fd or os.unlink not in os.supports_dir_fd:
        raise HarnessError("secure evidence finalization requires directory-descriptor support")
    parts = normalize_relative_path(relative)
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        current = os.open(root, directory_flags)
    except OSError as error:
        raise HarnessError("evidence root must be a regular non-symlink directory") from error
    try:
        for part in parts[:-1]:
            try:
                next_directory = os.open(part, directory_flags, dir_fd=current)
            except OSError as error:
                raise HarnessError("evidence path parent must be a regular non-symlink directory") from error
            os.close(current)
            current = next_directory
        return current, parts[-1]
    except BaseException:
        os.close(current)
        raise


def open_below_root(
    root: pathlib.Path,
    relative: str,
    flags: int,
    mode: int = 0o600,
) -> int:
    parent, leaf = _open_parent_below_root(root, relative)
    try:
        return os.open(leaf, flags | getattr(os, "O_NOFOLLOW", 0), mode, dir_fd=parent)
    except OSError as error:
        raise HarnessError("evidence file could not be opened without following symlinks") from error
    finally:
        os.close(parent)


def snapshot_evidence_files(
    root: pathlib.Path,
    relative_paths: Iterable[str],
    *,
    per_file_max_bytes: int = 64 * 1024 * 1024,
    total_max_bytes: int = 512 * 1024 * 1024,
) -> dict[str, bytes]:
    if per_file_max_bytes < 1 or total_max_bytes < per_file_max_bytes or total_max_bytes > 1024 * 1024 * 1024:
        raise HarnessError("evidence snapshot bounds are invalid")
    snapshots: dict[str, bytes] = {}
    total = 0
    for relative in relative_paths:
        normalize_relative_path(relative)
        if relative in snapshots:
            continue
        descriptor = open_below_root(root, relative, os.O_RDONLY)
        with os.fdopen(descriptor, "rb") as source:
            metadata = os.fstat(source.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > per_file_max_bytes:
                raise HarnessError("evidence file is not a bounded regular file")
            content = source.read(per_file_max_bytes + 1)
        if len(content) > per_file_max_bytes:
            raise HarnessError("evidence file exceeded its snapshot bound")
        total += len(content)
        if total > total_max_bytes:
            raise HarnessError("evidence snapshot exceeded its aggregate bound")
        snapshots[relative] = content
    return snapshots


def sha256_below_root(root: pathlib.Path, relative: str) -> str:
    descriptor = open_below_root(root, relative, os.O_RDONLY)
    digest = hashlib.sha256()
    with os.fdopen(descriptor, "rb") as source:
        metadata = os.fstat(source.fileno())
        if not stat.S_ISREG(metadata.st_mode):
            raise HarnessError("candidate artifact must be a regular file")
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_private_bytes_below_root(root: pathlib.Path, relative: str, content: bytes) -> None:
    descriptor = open_below_root(root, relative, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as destination:
            if destination.write(content) != len(content):
                raise HarnessError("private output write was incomplete")
            destination.flush()
            os.fsync(destination.fileno())
    except BaseException:
        try:
            unlink_below_root(root, relative)
        except (HarnessError, OSError):
            pass
        raise


def require_absent_below_root(root: pathlib.Path, relative: str) -> None:
    parent, leaf = _open_parent_below_root(root, relative)
    try:
        try:
            os.stat(leaf, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            return
        raise HarnessError("output path must not already exist")
    finally:
        os.close(parent)


def unlink_below_root(root: pathlib.Path, relative: str) -> None:
    parent, leaf = _open_parent_below_root(root, relative)
    try:
        os.unlink(leaf, dir_fd=parent)
    finally:
        os.close(parent)


def validate_permanent_text(content: bytes, forbidden_values: Iterable[bytes]) -> None:
    forbidden = tuple(value for value in forbidden_values if value)
    if any(value in content for value in forbidden):
        raise HarnessError("private runtime value reached permanent smoke evidence")
    if _CREDENTIAL_FIELD.search(content):
        raise HarnessError("credential-bearing field reached permanent smoke evidence")
    if _UUID_VALUE.search(content):
        raise HarnessError("UUID-shaped private identifier reached permanent smoke evidence")
    if _PRIVATE_JSON_FIELD.search(content):
        raise HarnessError("private identifier field reached permanent smoke evidence")
    try:
        decoded = content.decode("utf-8")
    except UnicodeDecodeError:
        return
    try:
        parsed = json.loads(decoded)
    except json.JSONDecodeError:
        return
    except RecursionError as error:
        raise HarnessError("JSON evidence exceeded its structural safety bound") from error
    forbidden_text = tuple(value.decode("utf-8") for value in forbidden)
    _validate_json_privacy(parsed, forbidden_text)


def scan_evidence_snapshots(snapshots: dict[str, bytes], forbidden_values: Iterable[bytes]) -> None:
    forbidden = tuple(value for value in forbidden_values if value)
    for content in snapshots.values():
        validate_permanent_text(content, forbidden)


def scan_evidence_privacy(paths: Iterable[pathlib.Path], forbidden_values: Iterable[bytes]) -> None:
    forbidden = tuple(value for value in forbidden_values if value)
    for path in paths:
        content = read_bounded_regular_file(path, 64 * 1024 * 1024)
        validate_permanent_text(content, forbidden)


def sha256_path(path: pathlib.Path) -> str:
    return sha256_file(path)


def evidence_index_from_snapshots(snapshots: dict[str, bytes]) -> dict[str, str]:
    return dict(sorted(
        (relative, hashlib.sha256(content).hexdigest())
        for relative, content in snapshots.items()
    ))


def evidence_index(root: pathlib.Path, paths: Iterable[pathlib.Path]) -> dict[str, str]:
    resolved_root = root.resolve()
    index: dict[str, str] = {}
    for path in paths:
        relative = path.resolve().relative_to(resolved_root).as_posix()
        digest = sha256_path(path)
        if relative in index:
            raise HarnessError("evidence index contains duplicate paths")
        index[relative] = digest
    return dict(sorted(index.items()))


def scenario_summary(claims: dict[str, dict[str, Any]]) -> dict[str, Any]:
    counts = {status: 0 for status in SMOKE_STATUSES}
    for claim in claims.values():
        counts[claim["status"]] += 1
    return {
        **counts,
        "protectedSmokeEligible": counts == {"PASS": len(SMOKE_SCENARIO_KEYS), "FAIL": 0, "BLOCKED": 0, "NOT RUN": 0},
    }


def protected_workflow_results(
    claims: dict[str, dict[str, Any]],
    version: str,
    *,
    evidence_validated: bool = False,
) -> dict[str, Any]:
    if not evidence_validated or not scenario_summary(claims)["protectedSmokeEligible"]:
        raise HarnessError("protected smoke workflow results require validated evidence and every scenario to pass")
    return {
        "observedExtensionVersion": version,
        "editions": {"community": "pass", "professional": "pass"},
        "scenarios": {key: "pass" for key in sorted(claims)},
    }


def json_object_from_bytes(content: bytes) -> dict[str, Any]:
    if len(content) > 4 * 1024 * 1024:
        raise HarnessError("JSON input exceeded its safety bound")
    try:
        value = json.loads(content.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise HarnessError("JSON input could not be read") from error
    if not isinstance(value, dict):
        raise HarnessError("JSON input must contain an object")
    return value


def read_json_object(path: pathlib.Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise HarnessError("JSON input must be a regular non-symlink file")
    return json_object_from_bytes(read_bounded_regular_file(path, 4 * 1024 * 1024))
