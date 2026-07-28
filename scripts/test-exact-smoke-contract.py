#!/usr/bin/env python3

from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import pathlib
import stat
import sys
import tempfile
import unittest
from unittest import mock

SCRIPTS = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))
import exact_smoke_contract as contract  # noqa: E402
from live_mcp_harness import HarnessError  # noqa: E402


def load_finalizer_module():
    spec = importlib.util.spec_from_file_location("exact_smoke_finalizer", SCRIPTS / "finalize-exact-burp-smoke.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


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


def catalog(edition: str) -> tuple[list[dict], list[dict], list[dict]]:
    tools = [correlation_tool()]
    if edition == "professional":
        tools.extend({"name": name} for name in sorted(contract.PROFESSIONAL_ONLY_TOOLS))
    expected = contract.EDITION_CATALOG_COUNTS[edition]
    while len(tools) < expected["tools"]:
        tools.append({"name": f"tool_{len(tools)}"})
    prompts = [{"name": f"prompt_{index}"} for index in range(expected["prompts"])]
    resources = [{"uri": f"burp://resource/{index}"} for index in range(expected["resources"])]
    return tools, prompts, resources


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
            "checks": {"loadedArtifactSha256": "matched"},
            "catalog": {
                "counts": expected,
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

    def test_edition_catalogs_enforce_counts_gating_and_correlation_bounds(self):
        for edition in contract.EDITION_CATALOG_COUNTS:
            tools, prompts, resources = catalog(edition)
            result = contract.validate_catalog(edition, tools, prompts, resources)
            self.assertEqual(contract.EDITION_CATALOG_COUNTS[edition], result["counts"])
            self.assertTrue(result["correlationReadOnly"])

        tools, prompts, resources = catalog("community")
        tools[-1] = {"name": next(iter(contract.PROFESSIONAL_ONLY_TOOLS))}
        with self.assertRaises(HarnessError):
            contract.validate_catalog("community", tools, prompts, resources)

        tools, prompts, resources = catalog("professional")
        tools[0]["inputSchema"]["properties"]["baselineRefs"]["maxItems"] = 17
        with self.assertRaises(HarnessError):
            contract.validate_catalog("professional", tools, prompts, resources)

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

    def test_privacy_scan_rejects_runtime_values_identifiers_and_credentials(self):
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
        )
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            for index, value in enumerate(bad_values):
                path = root / (f"bad-{index}.log" if index == len(bad_values) - 1 else f"bad-{index}.json")
                path.write_bytes(value)
                with self.assertRaises(HarnessError):
                    contract.scan_evidence_privacy([path], [b"private-marker"])
            good = root / "good.json"
            good.write_text('{"projectIdentifierRecorded":false,"status":"passed"}\n', encoding="utf-8")
            contract.scan_evidence_privacy([good], [b"private-marker"])


if __name__ == "__main__":
    unittest.main()
