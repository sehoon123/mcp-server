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

COMMON_TOOLS = frozenset(
    {
        "send_raw_http_request",
        "route_raw_http_request",
        "get_burp_options",
        "set_burp_options",
        "search_http_messages",
        "summarize_http_attack_surface",
        "correlate_http_activity",
        "check_scope",
        "update_scope",
        "compare_http_messages",
        "analyze_http_session_security",
        "save_workflow_preset",
        "list_workflow_presets",
        "delete_workflow_preset",
        "execute_workflow_preset",
        "get_http_message",
        "send_http_request_from_id",
        "route_http_message_from_id",
        "search_websocket_messages",
        "get_websocket_message_by_id",
        "set_burp_control_state",
    }
)
PROFESSIONAL_ONLY_TOOLS = frozenset(
    {
        "get_scanner_issues",
        "get_scanner_issue_by_id",
        "start_scanner_audit_from_ids",
        "get_scanner_audit",
        "cancel_scanner_audit",
        "generate_collaborator_payload",
        "get_collaborator_interactions",
    }
)
COMMUNITY_PROMPTS = frozenset(
    {
        "analyze_http_without_sending",
        "compare_http_references",
        "review_auth_session_handling",
        "plan_repeater_tests_without_sending",
    }
)
PROFESSIONAL_ONLY_PROMPTS = frozenset({"summarize_scanner_issue"})
FIXED_RESOURCES = frozenset(
    {
        "burp://diagnostics",
        "burp://project/summary",
        "burp://scope/summary",
    }
)
COMMON_RESOURCE_TEMPLATES = frozenset(
    {
        "burp://http/{projectId}/{source}/{id}",
        "burp://http/{projectId}/{source}/{id}/{part}",
        "burp://websocket/{projectId}/{id}",
        "burp://websocket/{projectId}/{id}/{variant}",
    }
)
PROFESSIONAL_ONLY_RESOURCE_TEMPLATES = frozenset(
    {
        "burp://scanner-issue/{projectId}/{id}",
        "burp://scanner-issue/{projectId}/{id}/{field}",
        "burp://scanner-issue/{projectId}/{id}/{field}/{evidenceIndex}",
    }
)
EDITION_CATALOG_IDENTIFIERS = {
    "community": {
        "tools": COMMON_TOOLS,
        "prompts": COMMUNITY_PROMPTS,
        "resources": FIXED_RESOURCES,
        "resourceTemplates": COMMON_RESOURCE_TEMPLATES,
    },
    "professional": {
        "tools": COMMON_TOOLS | PROFESSIONAL_ONLY_TOOLS,
        "prompts": COMMUNITY_PROMPTS | PROFESSIONAL_ONLY_PROMPTS,
        "resources": FIXED_RESOURCES,
        "resourceTemplates": COMMON_RESOURCE_TEMPLATES | PROFESSIONAL_ONLY_RESOURCE_TEMPLATES,
    },
}
EDITION_CATALOG_COUNTS = {
    edition: {catalog: len(identifiers) for catalog, identifiers in catalogs.items()}
    for edition, catalogs in EDITION_CATALOG_IDENTIFIERS.items()
}
SMOKE_SCENARIO_KEYS = frozenset(
    {
        "boundedLargeDataAndCancellation",
        "catalogEditionGating",
        "diagnosticsRedaction",
        "embeddedStdio",
        "loadUnload",
        "nativeHttp",
        "professionalScannerCollaborator",
        "routingNoHiddenNetwork",
        "serverLifecycle",
        "stableIdReplayIndependentApprovals",
        "unloadDuringBackgroundWork",
    }
)
SMOKE_STATUSES = ("PASS", "FAIL", "BLOCKED", "NOT RUN")
SCENARIO_REQUIRED_EDITIONS = {
    key: ("professional",) if key == "professionalScannerCollaborator" else ("community", "professional")
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
_JSON_UNICODE_ESCAPE = re.compile(r"\\u([0-9a-fA-F]{4})")
_MAX_JSON_PARSE_BYTES = 8 * 1024 * 1024
_MAX_JSON_STRUCTURAL_TOKENS = 100_000
_MAX_JSON_DEPTH = 128
_MAX_NESTED_JSON_DEPTH = 8
_MAX_NESTED_JSON_TEXT_BYTES = 8 * 1024 * 1024


def validate_release_identity(source_commit: str, jar_sha256: str, version: str) -> None:
    if not _HEX_40.fullmatch(source_commit):
        raise HarnessError("source commit must be 40 lowercase hexadecimal characters")
    if not _HEX_64.fullmatch(jar_sha256):
        raise HarnessError("JAR SHA-256 must be 64 lowercase hexadecimal characters")
    if not version or len(version) > 128 or any(ord(character) < 32 for character in version):
        raise HarnessError("server version is invalid")


def catalog_items(response: Any, key: str) -> list[dict[str, Any]]:
    try:
        result = response["result"]
        items = result[key]
    except (KeyError, TypeError):
        raise HarnessError("MCP catalog response was malformed")
    if not isinstance(result, dict) or not isinstance(items, list) or any(not isinstance(item, dict) for item in items):
        raise HarnessError("MCP catalog response was malformed")
    if result.get("nextCursor") is not None:
        raise HarnessError("paginated MCP catalogs cannot satisfy exact identifier validation")
    return items


def _catalog_identifiers(items: list[dict[str, Any]], field: str, label: str) -> frozenset[str]:
    identifiers = [item.get(field) for item in items]
    if any(not isinstance(identifier, str) or not identifier for identifier in identifiers):
        raise HarnessError(f"{label} catalog contains invalid identifiers")
    if len(set(identifiers)) != len(identifiers):
        raise HarnessError(f"{label} catalog contains duplicate identifiers")
    return frozenset(identifiers)


def validate_catalog(
    edition: str,
    tools: list[dict[str, Any]],
    prompts: list[dict[str, Any]],
    resources: list[dict[str, Any]],
    resource_templates: list[dict[str, Any]],
) -> dict[str, Any]:
    expected_identifiers = EDITION_CATALOG_IDENTIFIERS.get(edition)
    if expected_identifiers is None:
        raise HarnessError("edition must be community or professional")
    catalogs = {
        "tools": (tools, "name"),
        "prompts": (prompts, "name"),
        "resources": (resources, "uri"),
        "resourceTemplates": (resource_templates, "uriTemplate"),
    }
    if not all(
        isinstance(items, list) and all(isinstance(item, dict) for item in items)
        for items, _ in catalogs.values()
    ):
        raise HarnessError("MCP catalogs were not arrays of objects")
    counts = {label: len(items) for label, (items, _) in catalogs.items()}
    if counts != EDITION_CATALOG_COUNTS[edition]:
        raise HarnessError("catalog counts do not match the approved edition")
    for label, (items, field) in catalogs.items():
        actual = _catalog_identifiers(items, field, label)
        if actual != expected_identifiers[label]:
            raise HarnessError(f"{label} catalog identifiers do not match the approved edition")

    correlation = next((tool for tool in tools if tool.get("name") == "correlate_http_activity"), None)
    if correlation is None:
        raise HarnessError("correlation tool is absent")
    annotations = correlation.get("annotations") or {}
    input_schema = correlation.get("inputSchema") or {}
    if not isinstance(annotations, dict) or not isinstance(input_schema, dict):
        raise HarnessError("correlation tool schema was malformed")
    properties = input_schema.get("properties") or {}
    if not isinstance(properties, dict):
        raise HarnessError("correlation tool schema was malformed")
    if annotations.get("readOnlyHint") is not True or annotations.get("destructiveHint") is not False:
        raise HarnessError("correlation tool annotations changed")
    for name in ("baselineRefs", "comparisonRefs"):
        cohort_schema = properties.get(name) or {}
        if not isinstance(cohort_schema, dict) or cohort_schema.get("maxItems") != 16:
            raise HarnessError("correlation cohort bounds changed")

    return {
        "counts": counts,
        "identifierSets": "matched",
        "professionalOnlyTools": "absent" if edition == "community" else "present",
        "correlationReadOnly": True,
        "correlationCohortMaxItems": 16,
    }


def validate_scenario_claims(value: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(value, dict) or set(value) != SMOKE_SCENARIO_KEYS:
        raise HarnessError("scenario claims must contain exactly the release smoke keys")
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
        for relative in evidence:
            normalize_relative_path(relative)
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
    for relative in snapshots:
        normalize_relative_path(relative)
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
        if record_relative in objective_paths:
            raise HarnessError("scenario records and objective evidence paths must be disjoint")
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
        if (
            set(record) != expected_keys
            or type(record.get("schemaVersion")) is not int
            or record.get("schemaVersion") != 1
        ):
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
            normalize_relative_path(path)
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
        if record_paths.intersection(checked_paths):
            raise HarnessError("scenario records and objective evidence paths must be disjoint")
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
        parts = normalize_relative_path(relative)
        candidate = root
        for part in parts:
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


def _decode_evidence_text(content: bytes) -> str | None:
    if content.startswith((b"\x00\x00\xfe\xff", b"\xff\xfe\x00\x00")):
        encoding = "utf-32"
    elif content.startswith((b"\xfe\xff", b"\xff\xfe")):
        encoding = "utf-16"
    elif content.startswith(b"\xef\xbb\xbf"):
        encoding = "utf-8-sig"
    elif len(content) >= 4 and content[:3] == b"\x00\x00\x00":
        encoding = "utf-32-be"
    elif len(content) >= 4 and content[1:4] == b"\x00\x00\x00":
        encoding = "utf-32-le"
    elif len(content) >= 4 and content[0] == 0 and content[2] == 0:
        encoding = "utf-16-be"
    elif len(content) >= 4 and content[1] == 0 and content[3] == 0:
        encoding = "utf-16-le"
    else:
        encoding = "utf-8"
    recognized_text = encoding != "utf-8" or content.lstrip(b" \t\r\n")[:1] in {b"{", b"[", b'"'}
    try:
        return content.decode(encoding)
    except UnicodeDecodeError as error:
        if recognized_text:
            raise HarnessError("recognized text evidence is not valid in its declared encoding") from error
        return None


def _normalized_json_escape_text(value: str) -> str:
    return _JSON_UNICODE_ESCAPE.sub(
        lambda match: "\ufffd"
        if 0xD800 <= int(match.group(1), 16) <= 0xDFFF
        else chr(int(match.group(1), 16)),
        value,
    )


def _scan_decoded_text_privacy(value: str, forbidden_text: tuple[str, ...]) -> None:
    if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
        raise HarnessError("JSON evidence contained an unsupported surrogate value")
    normalized = _normalized_json_escape_text(value)
    if any(forbidden and (forbidden in value or forbidden in normalized) for forbidden in forbidden_text):
        raise HarnessError("private runtime value reached permanent smoke evidence")
    encoded = normalized.encode("utf-8")
    if _UUID_VALUE.search(encoded):
        raise HarnessError("UUID-shaped private identifier reached permanent smoke evidence")
    if _CREDENTIAL_FIELD.search(encoded):
        raise HarnessError("credential-bearing field reached permanent smoke evidence")
    if _PRIVATE_JSON_FIELD.search(encoded):
        raise HarnessError("private identifier field reached permanent smoke evidence")


def _json_text_candidate(value: str) -> str | None:
    stripped = value.lstrip("\ufeff \t\r\n")
    return stripped if stripped[:1] in {'{', '[', '"'} else None


def _validate_json_parse_bounds(value: str, encoded_bytes: int) -> None:
    if encoded_bytes > _MAX_JSON_PARSE_BYTES:
        raise HarnessError("JSON evidence exceeded its bounded parse size")
    in_string = False
    escaped = False
    depth = 0
    structural_tokens = 0
    for character in value:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
            structural_tokens += 1
        elif character in "[{":
            depth += 1
            structural_tokens += 1
            if depth > _MAX_JSON_DEPTH:
                raise HarnessError("JSON evidence exceeded its nesting bound")
        elif character in "]}":
            depth = max(depth - 1, 0)
        elif character in ",:":
            structural_tokens += 1
        if structural_tokens > _MAX_JSON_STRUCTURAL_TOKENS:
            raise HarnessError("JSON evidence exceeded its structural token bound")


def _validate_json_privacy(value: Any, forbidden_text: tuple[str, ...]) -> None:
    stack = [(value, 0)]
    visited = 0
    nested_json_text_bytes = 0
    while stack:
        visited += 1
        if visited > _MAX_JSON_STRUCTURAL_TOKENS:
            raise HarnessError("JSON evidence exceeded its structural safety bound")
        current, nested_depth = stack.pop()
        if isinstance(current, dict):
            for key, nested in current.items():
                if isinstance(key, str):
                    _scan_decoded_text_privacy(key, forbidden_text)
                    normalized = key.casefold()
                    if normalized in _CREDENTIAL_JSON_KEYS:
                        raise HarnessError("credential-bearing field reached permanent smoke evidence")
                    if normalized in _PRIVATE_JSON_KEYS:
                        raise HarnessError("private identifier field reached permanent smoke evidence")
                stack.append((nested, nested_depth))
        elif isinstance(current, list):
            stack.extend((nested, nested_depth) for nested in current)
        elif isinstance(current, str):
            _scan_decoded_text_privacy(current, forbidden_text)
            candidate = _json_text_candidate(current)
            if candidate is None:
                continue
            encoded_bytes = len(candidate.encode("utf-8"))
            nested_json_text_bytes += encoded_bytes
            if nested_depth >= _MAX_NESTED_JSON_DEPTH or nested_json_text_bytes > _MAX_NESTED_JSON_TEXT_BYTES:
                raise HarnessError("nested JSON evidence exceeded its privacy scan bound")
            _validate_json_parse_bounds(candidate, encoded_bytes)
            try:
                nested_value = json.loads(candidate)
            except json.JSONDecodeError:
                continue
            except RecursionError as error:
                raise HarnessError("nested JSON evidence exceeded its structural safety bound") from error
            if isinstance(nested_value, (dict, list, str)):
                stack.append((nested_value, nested_depth + 1))


def normalize_relative_path(relative: str) -> tuple[str, ...]:
    if not isinstance(relative, str) or "\\" in relative or any(ord(character) < 32 for character in relative):
        raise HarnessError("evidence path contains unsupported characters")
    candidate = pathlib.PurePosixPath(relative)
    if candidate.is_absolute() or ".." in candidate.parts or not candidate.parts:
        raise HarnessError("evidence path must stay below the evidence root")
    if relative != candidate.as_posix():
        raise HarnessError("evidence path must use canonical POSIX spelling")
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
    opened_file_identities: set[tuple[int, int]] | None = None,
) -> dict[str, bytes]:
    if per_file_max_bytes < 1 or total_max_bytes < per_file_max_bytes or total_max_bytes > 1024 * 1024 * 1024:
        raise HarnessError("evidence snapshot bounds are invalid")
    snapshots: dict[str, bytes] = {}
    if opened_file_identities is None:
        opened_file_identities = set()
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
            file_identity = (metadata.st_dev, metadata.st_ino)
            if file_identity in opened_file_identities:
                raise HarnessError("distinct evidence paths must not name the same physical file")
            opened_file_identities.add(file_identity)
            content = source.read(per_file_max_bytes + 1)
        if len(content) > per_file_max_bytes:
            raise HarnessError("evidence file exceeded its snapshot bound")
        total += len(content)
        if total > total_max_bytes:
            raise HarnessError("evidence snapshot exceeded its aggregate bound")
        snapshots[relative] = content
    return snapshots


def sha256_below_root(
    root: pathlib.Path,
    relative: str,
    *,
    opened_file_identities: set[tuple[int, int]] | None = None,
) -> str:
    descriptor = open_below_root(root, relative, os.O_RDONLY)
    digest = hashlib.sha256()
    with os.fdopen(descriptor, "rb") as source:
        metadata = os.fstat(source.fileno())
        if not stat.S_ISREG(metadata.st_mode):
            raise HarnessError("candidate artifact must be a regular file")
        if opened_file_identities is not None:
            file_identity = (metadata.st_dev, metadata.st_ino)
            if file_identity in opened_file_identities:
                raise HarnessError("distinct evidence paths must not name the same physical file")
            opened_file_identities.add(file_identity)
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
        forbidden_text = tuple(value.decode("utf-8") for value in forbidden)
    except UnicodeDecodeError as error:
        raise HarnessError("forbidden evidence values must be UTF-8 text") from error
    decoded = _decode_evidence_text(content)
    if decoded is None:
        return
    _scan_decoded_text_privacy(decoded, forbidden_text)
    candidate = _json_text_candidate(decoded)
    if candidate is None:
        return
    _validate_json_parse_bounds(candidate, len(content))
    try:
        parsed = json.loads(candidate)
    except json.JSONDecodeError:
        return
    except RecursionError as error:
        raise HarnessError("JSON evidence exceeded its structural safety bound") from error
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
        raise HarnessError("release smoke workflow results require validated evidence and every scenario to pass")
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
