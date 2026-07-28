#!/usr/bin/env python3

from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import pathlib
import re
import stat
import sys
import tempfile
import unittest
from unittest import mock

SCRIPTS = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))
import exact_smoke_contract as contract  # noqa: E402
from live_mcp_harness import HarnessError  # noqa: E402


def load_script_module(module_name: str, filename: str):
    spec = importlib.util.spec_from_file_location(module_name, SCRIPTS / filename)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def load_finalizer_module():
    return load_script_module("exact_smoke_finalizer", "finalize-exact-burp-smoke.py")


def load_preflight_module():
    return load_script_module("exact_smoke_preflight", "run-exact-burp-preflight.py")


def correlation_tool() -> dict:
    return {
        "name": "correlate_http_activity",
        "annotations": {"readOnlyHint": True, "destructiveHint": False},
        "inputSchema": {
            "properties": {
                "baselineRefs": {"maxItems": 16},
                "comparisonRefs": {"maxItems": 16},
            }
        },
    }


def catalog(edition: str) -> tuple[list[dict], list[dict], list[dict], list[dict]]:
    expected = contract.EDITION_CATALOG_IDENTIFIERS[edition]
    tools = [
        correlation_tool() if name == "correlate_http_activity" else {"name": name}
        for name in sorted(expected["tools"])
    ]
    prompts = [{"name": name} for name in sorted(expected["prompts"])]
    resources = [{"uri": uri} for uri in sorted(expected["resources"])]
    resource_templates = [
        {"uriTemplate": uri} for uri in sorted(expected["resourceTemplates"])
    ]
    return tools, prompts, resources, resource_templates


def claims(status: str = "NOT RUN") -> dict[str, dict]:
    return {
        key: {
            "status": status,
            "evidence": ["evidence/proof.json"] if status in {"PASS", "FAIL"} else [],
            "notes": "Bounded test note.",
        }
        for key in contract.SMOKE_SCENARIO_KEYS
    }


def build_finalizer_fixture(root: pathlib.Path) -> tuple[str, str, str]:
    source = "a" * 40
    version = "4.11.0-rc.2"
    evidence = root / "evidence"
    assets = root / "assets"
    evidence.mkdir()
    assets.mkdir()
    candidate = assets / "candidate.jar"
    candidate.write_bytes(b"exact-candidate")
    forbidden = root / "private-forbidden-value"
    forbidden.write_text("private-runtime-marker", encoding="utf-8")
    forbidden.chmod(0o600)
    jar = hashlib.sha256(candidate.read_bytes()).hexdigest()

    for edition, expected in contract.EDITION_CATALOG_COUNTS.items():
        report = {
            "schemaVersion": 1,
            "status": "passed",
            "edition": edition,
            "sourceCommit": source,
            "candidateJarSha256": jar,
            "expectedServerVersion": version,
            "protocolVersion": "2025-11-25",
            "projectIdentifierRecorded": False,
            "sessionIdentifierRecorded": False,
            "bearerRecorded": False,
            "rawTrafficRecorded": False,
            "sessionDeleteAccepted": True,
            "checks": {
                "authenticatedIdentity": "passed",
                "loadedArtifactSha256": "matched",
                "boundedReadOnlyToolCall": "passed",
                "diagnosticsRedaction": "passed",
                "projectBinding": "passed",
                "resourceCatalog": "passed",
                "unauthenticatedStatus401": "passed",
            },
            "catalog": {
                "counts": expected,
                "identifierSets": "matched",
                "professionalOnlyTools": "absent" if edition == "community" else "present",
                "correlationReadOnly": True,
                "correlationCohortMaxItems": 16,
            },
        }
        (evidence / f"{edition}-preflight.json").write_text(json.dumps(report), encoding="utf-8")

    scenario_claims = claims("PASS")
    for scenario in sorted(contract.SMOKE_SCENARIO_KEYS):
        proof_relative = f"evidence/{scenario}-proof.json"
        record_relative = f"evidence/{scenario}-record.json"
        proof = root / proof_relative
        proof.write_text(json.dumps({"scenario": scenario, "status": "passed"}), encoding="utf-8")
        digest = hashlib.sha256(proof.read_bytes()).hexdigest()
        record = {
            "schemaVersion": 1,
            "scenario": scenario,
            "status": "PASS",
            "sourceCommit": source,
            "candidateJarSha256": jar,
            "serverVersion": version,
            "editions": list(contract.SCENARIO_REQUIRED_EDITIONS[scenario]),
            "checks": [{
                "name": "objective-check",
                "path": proof_relative,
                "sha256": digest,
                "result": "pass",
            }],
        }
        (root / record_relative).write_text(json.dumps(record), encoding="utf-8")
        scenario_claims[scenario]["evidence"] = [record_relative, proof_relative]
    (root / "SCENARIO_CLAIMS.json").write_text(
        json.dumps({"schemaVersion": 1, "scenarios": scenario_claims}),
        encoding="utf-8",
    )
    return source, jar, version


class ExactSmokeContractTest(unittest.TestCase):
    def test_protected_workflow_scenario_identifiers_match_the_local_contract(self):
        workflow = (SCRIPTS.parent / ".github/workflows/release-smoke.yml").read_text(encoding="utf-8")
        step_marker = "      - name: Download and verify the immutable draft bytes\n"
        self.assertEqual(1, workflow.count(step_marker))
        protected_step = workflow.split(step_marker, maxsplit=1)[1].split("\n      - name: ", maxsplit=1)[0]
        self.assertIn("jq -e --arg version", protected_step)
        self.assertIn("' <<<\"$RESULTS_JSON\" > \"$RUNNER_TEMP/smoke-claims.json\"", protected_step)
        match = re.search(
            r"\(\.scenarios \| keys \| sort\) == \[(.*?)\]\s+and\s+\(\[\.scenarios\[\]\]",
            protected_step,
            flags=re.DOTALL,
        )
        self.assertIsNotNone(match, "protected workflow scenario assertion was not found")
        scenario_array = match.group(1)
        workflow_scenarios = re.findall(r'^\s+"([A-Za-z][A-Za-z0-9]+)",?\s*$', scenario_array, flags=re.MULTILINE)
        self.assertEqual(len(contract.SMOKE_SCENARIO_KEYS), len(workflow_scenarios))
        self.assertEqual(sorted(contract.SMOKE_SCENARIO_KEYS), workflow_scenarios)
        self.assertEqual(",".join(f'\n              \"{key}\"' for key in workflow_scenarios), scenario_array.rstrip())

    def test_release_identity_is_exact_and_bounded(self):
        contract.validate_release_identity("a" * 40, "b" * 64, "4.11.0-rc.2")
        for source, digest, version in (
            ("A" * 40, "b" * 64, "4.11.0-rc.2"),
            ("a" * 39, "b" * 64, "4.11.0-rc.2"),
            ("a" * 40, "b" * 63, "4.11.0-rc.2"),
            ("a" * 40, "b" * 64, "bad\nversion"),
        ):
            with self.assertRaises(HarnessError):
                contract.validate_release_identity(source, digest, version)

    def test_edition_catalogs_enforce_exact_identifiers_and_correlation_bounds(self):
        for edition in contract.EDITION_CATALOG_COUNTS:
            tools, prompts, resources, templates = catalog(edition)
            result = contract.validate_catalog(edition, tools, prompts, resources, templates)
            self.assertEqual(contract.EDITION_CATALOG_COUNTS[edition], result["counts"])
            self.assertEqual("matched", result["identifierSets"])
            self.assertTrue(result["correlationReadOnly"])

        catalog_fields = ((0, "name"), (1, "name"), (2, "uri"), (3, "uriTemplate"))
        for edition in contract.EDITION_CATALOG_IDENTIFIERS:
            for catalog_index, field in catalog_fields:
                values = list(catalog(edition))
                values[catalog_index][-1] = {field: "count-preserving-substitution"}
                with self.assertRaises(HarnessError):
                    contract.validate_catalog(edition, *values)

                values = list(catalog(edition))
                values[catalog_index][-1] = dict(values[catalog_index][0])
                with self.assertRaises(HarnessError):
                    contract.validate_catalog(edition, *values)

        community_catalog = catalog("community")
        professional_catalog = catalog("professional")
        for catalog_index, field, label in (
            (0, "name", "tools"),
            (1, "name", "prompts"),
            (3, "uriTemplate", "resourceTemplates"),
        ):
            professional_only = (
                contract.EDITION_CATALOG_IDENTIFIERS["professional"][label]
                - contract.EDITION_CATALOG_IDENTIFIERS["community"][label]
            )
            community_values = list(catalog("community"))
            community_values[catalog_index][-1] = {field: sorted(professional_only)[0]}
            with self.assertRaises(HarnessError):
                contract.validate_catalog("community", *community_values)

            professional_values = list(catalog("professional"))
            professional_values[catalog_index] = community_catalog[catalog_index]
            with self.assertRaises(HarnessError):
                contract.validate_catalog("professional", *professional_values)

        tools, prompts, resources, templates = professional_catalog
        correlation = next(tool for tool in tools if tool.get("name") == "correlate_http_activity")
        correlation["inputSchema"]["properties"]["baselineRefs"]["maxItems"] = 17
        with self.assertRaises(HarnessError):
            contract.validate_catalog("professional", tools, prompts, resources, templates)

        for edition in contract.EDITION_CATALOG_IDENTIFIERS:
            tools, prompts, resources, templates = catalog(edition)
            with self.assertRaises(HarnessError):
                contract.validate_catalog(edition, tools[:-1], prompts, resources, templates)
            with self.assertRaises(HarnessError):
                contract.validate_catalog(
                    edition,
                    tools + [{"name": "unexpected_tool"}],
                    prompts,
                    resources,
                    templates,
                )
            malformed = list(catalog(edition))
            malformed[1][-1] = "not-an-object"
            with self.assertRaises(HarnessError):
                contract.validate_catalog(edition, *malformed)

    def test_catalog_response_rejects_pagination_instead_of_attesting_only_the_first_page(self):
        response = {"result": {"tools": [{"name": "one"}]}}
        self.assertEqual([{"name": "one"}], contract.catalog_items(response, "tools"))
        for cursor in ("later-page", ""):
            with self.assertRaises(HarnessError):
                contract.catalog_items(
                    {"result": {"tools": [{"name": "one"}], "nextCursor": cursor}},
                    "tools",
                )
        with self.assertRaises(HarnessError):
            contract.catalog_items({"result": {"tools": ["not-an-object"]}}, "tools")

    def test_finalizer_requires_the_exact_current_preflight_check_set(self):
        finalizer = load_finalizer_module()
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            source, jar, version = build_finalizer_fixture(root)
            report = json.loads((root / "evidence/community-preflight.json").read_text(encoding="utf-8"))
            finalizer.validate_preflight(report, "community", source, jar, version)

            missing = json.loads(json.dumps(report))
            missing["checks"].pop("boundedReadOnlyToolCall")
            with self.assertRaises(HarnessError):
                finalizer.validate_preflight(missing, "community", source, jar, version)

            for schema_version in (None, 999, True, False, 1.0, "1"):
                unsupported = json.loads(json.dumps(report))
                if schema_version is None:
                    unsupported.pop("schemaVersion")
                else:
                    unsupported["schemaVersion"] = schema_version
                with self.assertRaises(HarnessError):
                    finalizer.validate_preflight(unsupported, "community", source, jar, version)

            stale = json.loads(json.dumps(report))
            stale["checks"]["boundedNoSideEffectToolCall"] = stale["checks"].pop("boundedReadOnlyToolCall")
            with self.assertRaises(HarnessError):
                finalizer.validate_preflight(stale, "community", source, jar, version)

            extra_catalog_field = json.loads(json.dumps(report))
            extra_catalog_field["catalog"]["staleAssertion"] = True
            with self.assertRaises(HarnessError):
                finalizer.validate_preflight(extra_catalog_field, "community", source, jar, version)

    def test_preflight_scope_probe_requires_exact_project_bound_result_identity(self):
        preflight = load_preflight_module()
        project_id = "private-project-id"
        target_url = "https://example.invalid/"
        valid = {
            "status": "ok",
            "projectId": project_id,
            "targets": [{"index": 0, "url": target_url, "inScope": False}],
        }
        preflight.validate_scope_probe(valid, project_id, target_url)

        invalid_results = []
        for replacement in (
            {"status": "burp_error"},
            {"projectId": "other-project"},
            {"targets": []},
            {"targets": [{"index": 1, "url": target_url, "inScope": False}]},
            {"targets": [{"index": 0, "url": "https://other.invalid/", "inScope": False}]},
            {"targets": [{"index": 0, "url": target_url, "inScope": 0}]},
        ):
            candidate = json.loads(json.dumps(valid))
            candidate.update(replacement)
            invalid_results.append(candidate)
        invalid_results.append("not-an-object")

        for invalid in invalid_results:
            with self.assertRaises(HarnessError):
                preflight.validate_scope_probe(invalid, project_id, target_url)

    def test_scenario_contract_is_exact_and_never_infers_not_run_as_pass(self):
        not_run = contract.validate_scenario_claims(claims())
        summary = contract.scenario_summary(not_run)
        self.assertEqual(13, summary["NOT RUN"])
        self.assertFalse(summary["protectedSmokeEligible"])

        passed = contract.validate_scenario_claims(claims("PASS"))
        self.assertTrue(contract.scenario_summary(passed)["protectedSmokeEligible"])
        with self.assertRaises(HarnessError):
            contract.protected_workflow_results(passed, "4.11.0-rc.2")
        workflow = contract.protected_workflow_results(
            passed,
            "4.11.0-rc.2",
            evidence_validated=True,
        )
        self.assertEqual({"community": "pass", "professional": "pass"}, workflow["editions"])
        self.assertEqual(13, len(workflow["scenarios"]))
        with self.assertRaises(HarnessError):
            contract.protected_workflow_results(not_run, "4.11.0-rc.2", evidence_validated=True)

        missing = claims()
        missing.pop(next(iter(missing)))
        with self.assertRaises(HarnessError):
            contract.validate_scenario_claims(missing)
        empty_pass = claims("PASS")
        empty_pass[next(iter(empty_pass))]["evidence"] = []
        with self.assertRaises(HarnessError):
            contract.validate_scenario_claims(empty_pass)

    def test_scenario_record_binds_candidate_editions_and_objective_evidence_digest(self):
        source = "a" * 40
        jar = "b" * 64
        version = "4.11.0-rc.2"
        scenario = "catalogEditionGating"
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            evidence = root / "evidence"
            evidence.mkdir()
            proof = evidence / "catalog.json"
            proof.write_text('{"status":"passed"}\n', encoding="utf-8")
            digest = hashlib.sha256(proof.read_bytes()).hexdigest()
            record = evidence / "catalog-record.json"
            record.write_text(
                json.dumps({
                    "schemaVersion": 1,
                    "scenario": scenario,
                    "status": "PASS",
                    "sourceCommit": source,
                    "candidateJarSha256": jar,
                    "serverVersion": version,
                    "editions": ["community", "professional"],
                    "checks": [{
                        "name": "catalog-gating",
                        "path": "evidence/catalog.json",
                        "sha256": digest,
                        "result": "pass",
                    }],
                }),
                encoding="utf-8",
            )
            value = claims()
            value[scenario] = {
                "status": "PASS",
                "evidence": ["evidence/catalog-record.json", "evidence/catalog.json"],
                "notes": "Bound candidate evidence.",
            }
            normalized = contract.validate_scenario_claims(value)
            paths = contract.validate_scenario_evidence_records(root, normalized, source, jar, version)
            self.assertEqual(2, len(paths))

            record_document = json.loads(record.read_text(encoding="utf-8"))
            record_document["schemaVersion"] = True
            record.write_text(json.dumps(record_document), encoding="utf-8")
            with self.assertRaises(HarnessError):
                contract.validate_scenario_evidence_records(root, normalized, source, jar, version)
            record_document["schemaVersion"] = 1
            record.write_text(json.dumps(record_document), encoding="utf-8")

            proof.write_text('{"status":"changed"}\n', encoding="utf-8")
            with self.assertRaises(HarnessError):
                contract.validate_scenario_evidence_records(root, normalized, source, jar, version)

    def test_objective_evidence_cannot_be_shared_across_scenario_records(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            source, jar, version = build_finalizer_fixture(root)
            document = json.loads((root / "SCENARIO_CLAIMS.json").read_text(encoding="utf-8"))
            first, second = sorted(contract.SMOKE_SCENARIO_KEYS)[:2]
            first_proof = document["scenarios"][first]["evidence"][1]
            second_record_relative = document["scenarios"][second]["evidence"][0]
            second_record_path = root / second_record_relative
            second_record = json.loads(second_record_path.read_text(encoding="utf-8"))
            second_record["checks"][0]["path"] = first_proof
            second_record["checks"][0]["sha256"] = hashlib.sha256((root / first_proof).read_bytes()).hexdigest()
            second_record_path.write_text(json.dumps(second_record), encoding="utf-8")
            document["scenarios"][second]["evidence"][1] = first_proof
            normalized = contract.validate_scenario_claims(document["scenarios"])
            relative = list(dict.fromkeys(
                path for claim in normalized.values() for path in claim["evidence"]
            ))
            snapshots = contract.snapshot_evidence_files(root, relative)
            with self.assertRaises(HarnessError):
                contract.validate_scenario_evidence_snapshots(snapshots, normalized, source, jar, version)

            first_record = document["scenarios"][first]["evidence"][0]
            second_record["checks"][0]["path"] = first_record
            second_record["checks"][0]["sha256"] = hashlib.sha256((root / first_record).read_bytes()).hexdigest()
            second_record_path.write_text(json.dumps(second_record), encoding="utf-8")
            document["scenarios"][second]["evidence"][1] = first_record
            normalized = contract.validate_scenario_claims(document["scenarios"])
            relative = list(dict.fromkeys(
                path for claim in normalized.values() for path in claim["evidence"]
            ))
            snapshots = contract.snapshot_evidence_files(root, relative)
            with self.assertRaises(HarnessError):
                contract.validate_scenario_evidence_snapshots(snapshots, normalized, source, jar, version)

    def test_evidence_paths_are_regular_below_root_and_indexed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            evidence = root / "evidence"
            evidence.mkdir()
            proof = evidence / "proof.json"
            proof.write_text('{"status":"passed"}\n', encoding="utf-8")
            paths = contract.resolve_evidence_paths(root, ["evidence/proof.json"])
            index = contract.evidence_index(root, paths)
            self.assertEqual(["evidence/proof.json"], list(index))
            with self.assertRaises(HarnessError):
                contract.resolve_evidence_paths(root, ["../proof.json"])
            link = evidence / "link.json"
            link.symlink_to(proof)
            with self.assertRaises(HarnessError):
                contract.resolve_evidence_paths(root, ["evidence/link.json"])
            linked_directory = root / "linked"
            linked_directory.symlink_to(evidence, target_is_directory=True)
            with self.assertRaises(HarnessError):
                contract.resolve_evidence_paths(root, ["linked/proof.json"])
            with self.assertRaises(HarnessError):
                contract.snapshot_evidence_files(root, ["linked/proof.json"])
            with self.assertRaises(HarnessError):
                contract.require_absent_below_root(root, "linked/new-output.json")

            for alias in ("evidence//proof.json", "./evidence/proof.json", "evidence/./proof.json"):
                with self.assertRaises(HarnessError):
                    contract.snapshot_evidence_files(root, [alias])

            hard_link = evidence / "hard-link.json"
            hard_link.hardlink_to(proof)
            with self.assertRaises(HarnessError):
                contract.snapshot_evidence_files(
                    root,
                    ["evidence/proof.json", "evidence/hard-link.json"],
                )
            opened_file_identities: set[tuple[int, int]] = set()
            contract.sha256_below_root(
                root,
                "evidence/proof.json",
                opened_file_identities=opened_file_identities,
            )
            with self.assertRaises(HarnessError):
                contract.snapshot_evidence_files(
                    root,
                    ["evidence/hard-link.json"],
                    opened_file_identities=opened_file_identities,
                )

            aliased_claims = claims()
            scenario = sorted(contract.SMOKE_SCENARIO_KEYS)[0]
            aliased_claims[scenario] = {
                "status": "PASS",
                "evidence": ["evidence/record.json", "evidence//proof.json"],
                "notes": "Non-canonical evidence path must fail closed.",
            }
            with self.assertRaises(HarnessError):
                contract.validate_scenario_claims(aliased_claims)

    def test_finalizer_creates_workflow_input_only_for_candidate_bound_all_pass_evidence(self):
        finalizer = load_finalizer_module()
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            source, jar, version = build_finalizer_fixture(root)

            def invoke(claims_file: str, matrix: str, workflow: str) -> int:
                arguments = [
                    "finalize-exact-burp-smoke.py",
                    "--root", str(root),
                    "--community-preflight", "evidence/community-preflight.json",
                    "--professional-preflight", "evidence/professional-preflight.json",
                    "--scenario-claims", claims_file,
                    "--candidate-jar", "assets/candidate.jar",
                    "--expected-jar-sha256", jar,
                    "--expected-source-commit", source,
                    "--expected-server-version", version,
                    "--forbidden-value-file", str(root / "private-forbidden-value"),
                    "--output", matrix,
                    "--workflow-results-output", workflow,
                    "--require-all-pass",
                ]
                with mock.patch.object(sys, "argv", arguments), mock.patch.object(
                    finalizer,
                    "git_output",
                    side_effect=lambda _root, *args: source if args[0] == "rev-parse" else "",
                ), contextlib.redirect_stdout(io.StringIO()):
                    return finalizer.main()

            self.assertEqual(0, invoke("SCENARIO_CLAIMS.json", "MATRIX.json", "WORKFLOW.json"))
            matrix = json.loads((root / "MATRIX.json").read_text(encoding="utf-8"))
            workflow = json.loads((root / "WORKFLOW.json").read_text(encoding="utf-8"))
            self.assertTrue(matrix["summary"]["protectedSmokeEligible"])
            self.assertEqual(13, len(workflow["scenarios"]))
            self.assertEqual(0o600, stat.S_IMODE((root / "MATRIX.json").stat().st_mode))
            self.assertEqual(0o600, stat.S_IMODE((root / "WORKFLOW.json").stat().st_mode))

            withheld = json.loads((root / "SCENARIO_CLAIMS.json").read_text(encoding="utf-8"))
            blocked_key = "dataApprovalAndProjectTransition"
            withheld["scenarios"][blocked_key] = {
                "status": "BLOCKED",
                "evidence": [],
                "notes": "No safe live transition trigger.",
            }
            (root / "WITHHELD_CLAIMS.json").write_text(json.dumps(withheld), encoding="utf-8")
            self.assertEqual(1, invoke("WITHHELD_CLAIMS.json", "WITHHELD_MATRIX.json", "ABSENT_WORKFLOW.json"))
            withheld_matrix = json.loads((root / "WITHHELD_MATRIX.json").read_text(encoding="utf-8"))
            self.assertFalse(withheld_matrix["summary"]["protectedSmokeEligible"])
            self.assertEqual("WITHHOLD", withheld_matrix["releaseDisposition"])
            self.assertFalse((root / "ABSENT_WORKFLOW.json").exists())

    def test_finalizer_rejects_cross_batch_physical_file_aliases(self):
        finalizer = load_finalizer_module()
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            source, jar, version = build_finalizer_fixture(root)
            claims_document = json.loads((root / "SCENARIO_CLAIMS.json").read_text(encoding="utf-8"))
            scenario = sorted(contract.SMOKE_SCENARIO_KEYS)[0]
            claim = claims_document["scenarios"][scenario]
            record_path = root / claim["evidence"][0]
            proof_path = root / claim["evidence"][1]
            preflight_path = root / "evidence/community-preflight.json"
            proof_path.unlink()
            proof_path.hardlink_to(preflight_path)
            record = json.loads(record_path.read_text(encoding="utf-8"))
            record["checks"][0]["sha256"] = hashlib.sha256(preflight_path.read_bytes()).hexdigest()
            record_path.write_text(json.dumps(record), encoding="utf-8")

            arguments = [
                "finalize-exact-burp-smoke.py",
                "--root", str(root),
                "--community-preflight", "evidence/community-preflight.json",
                "--professional-preflight", "evidence/professional-preflight.json",
                "--scenario-claims", "SCENARIO_CLAIMS.json",
                "--candidate-jar", "assets/candidate.jar",
                "--expected-jar-sha256", jar,
                "--expected-source-commit", source,
                "--expected-server-version", version,
                "--forbidden-value-file", str(root / "private-forbidden-value"),
                "--output", "MATRIX.json",
                "--require-all-pass",
            ]
            with mock.patch.object(sys, "argv", arguments), mock.patch.object(
                finalizer,
                "git_output",
                side_effect=lambda _root, *args: source if args[0] == "rev-parse" else "",
            ), contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(HarnessError):
                    finalizer.main()
            self.assertFalse((root / "MATRIX.json").exists())

    def test_privacy_scan_rejects_runtime_values_identifiers_and_credentials(self):
        malformed_unicode_text = (
            b"\xff\xfe" + '{"projectId":"'.encode("utf-16-le") + b"\x00\xd8" + '"}'.encode("utf-16-le"),
            b"\xfe\xff" + '{"projectId":"'.encode("utf-16-be") + b"\xd8\x00" + '"}'.encode("utf-16-be"),
            b"\xff\xfe\x00\x00" + '{"projectId":"'.encode("utf-32-le") + b"\x00\xd8\x00\x00" + '"}'.encode("utf-32-le"),
            b"\x00\x00\xfe\xff" + '{"projectId":"'.encode("utf-32-be") + b"\x00\x00\xd8\x00" + '"}'.encode("utf-32-be"),
            '{"projectId":"'.encode("utf-16-le") + b"\x00\xd8" + '"}'.encode("utf-16-le"),
        )
        nested_json_values = (
            '{"projectId":"opaque"}',
            r'{"session\u0049d":"opaque"}',
            r'{"Authoriz\u0061tion":"Bearer redacted"}',
        )
        bad_values = (
            b'{"value":"private-marker"}\n',
            b'{"projectId":"opaque"}\n',
            b'{"value":"123e4567-e89b-12d3-a456-426614174000"}\n',
            b'Authorization: Bearer redacted\n',
            b'{"Authorization":"Bearer redacted"}\n',
            b'{"Set-Cookie" : "redacted"}\n',
            b'{"Authoriz\\u0061tion":"Bearer redacted"}\n',
            b'{"session\\u0049d":"opaque"}\n',
            b'{"value":"private-\\u006darker"}\n',
        ) + tuple(
            json.dumps({"log": nested}).encode("utf-8")
            for nested in nested_json_values
        ) + (
            b'\xef\xbb\xbf{"project\\u0049d":"opaque"}',
            '{"projectId":"opaque"}'.encode("utf-16"),
            '{"projectId":"opaque"}'.encode("utf-16-le"),
            '{"value":"private-marker"}'.encode("utf-32"),
            json.dumps({"log": '\ufeff' + r'{"project\u0049d":"opaque"}'}).encode("utf-8"),
            b'{"value":"\\ud800"}',
            b'{"safe\\ud800":"value"}',
        ) + malformed_unicode_text
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            for index, value in enumerate(bad_values):
                path = root / (f"bad-{index}.log" if index == len(bad_values) - 1 else f"bad-{index}.json")
                path.write_bytes(value)
                with self.assertRaises(HarnessError):
                    contract.scan_evidence_privacy([path], [b"private-marker"])
            escaped_forbidden_key = json.dumps({"private😀": "value"}).encode("utf-8")
            with self.assertRaises(HarnessError):
                contract.validate_permanent_text(escaped_forbidden_key, ("private😀".encode("utf-8"),))
            good = root / "good.json"
            good.write_text('{"projectIdentifierRecorded":false,"status":"passed"}\n', encoding="utf-8")
            contract.scan_evidence_privacy([good], [b"private-marker"])

    def test_privacy_json_parser_bounds_apply_before_dom_construction(self):
        dense_array = ("[" + ",".join("0" for _ in range(100_001)) + "]").encode("utf-8")
        with self.assertRaises(HarnessError):
            contract.validate_permanent_text(dense_array, ())

        deeply_nested = ("[" * 129 + "0" + "]" * 129).encode("utf-8")
        with self.assertRaises(HarnessError):
            contract.validate_permanent_text(deeply_nested, ())

        oversized_json = b'{"value":"' + b"a" * (8 * 1024 * 1024) + b'"}'
        with self.assertRaises(HarnessError):
            contract.validate_permanent_text(oversized_json, ())


if __name__ == "__main__":
    unittest.main()
