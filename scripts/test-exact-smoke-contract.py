#!/usr/bin/env python3

from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import os
import pathlib
import re
import stat
import subprocess
import sys
import tempfile
import textwrap
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


def lifecycle_report(edition: str, source: str, jar: str, version: str) -> dict:
    return {
        "schemaVersion": 1,
        "status": "passed",
        "edition": edition,
        "sourceCommit": source,
        "candidateJarSha256": jar,
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


def lifecycle_token_arguments(root: pathlib.Path) -> list[str]:
    arguments: list[str] = []
    for edition in ("community", "professional"):
        for stage in (
            "before-project-switch",
            "after-project-switch",
            "after-restart",
            "after-rotation",
        ):
            arguments.extend([f"--{edition}-token-{stage}", str(root / f"private-{edition}-token-{stage}")])
    return arguments


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
    for edition, initial, rotated in (
        ("community", "c" * 43, "d" * 43),
        ("professional", "p" * 43, "r" * 43),
    ):
        stage_values = {
            "before-project-switch": initial,
            "after-project-switch": initial,
            "after-restart": initial,
            "after-rotation": rotated,
        }
        for stage, value in stage_values.items():
            token_file = root / f"private-{edition}-token-{stage}"
            token_file.write_text(value, encoding="utf-8")
            token_file.chmod(0o600)
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
        (evidence / f"{edition}-bearer-lifecycle.json").write_text(
            json.dumps(lifecycle_report(edition, source, jar, version)),
            encoding="utf-8",
        )

    scenario_claims = claims("PASS")
    for scenario in sorted(contract.SMOKE_SCENARIO_KEYS):
        proof_relative = f"evidence/{scenario}-proof.json"
        record_relative = f"evidence/{scenario}-record.json"
        proof = root / proof_relative
        proof.write_text(json.dumps({"scenario": scenario, "status": "passed"}), encoding="utf-8")
        objective_relatives = [proof_relative]
        if scenario == "serverLifecycle":
            objective_relatives.extend([
                "evidence/community-bearer-lifecycle.json",
                "evidence/professional-bearer-lifecycle.json",
            ])
        checks = [
            {
                "name": "objective-check" if index == 0 else f"{pathlib.PurePosixPath(relative).stem}-check",
                "path": relative,
                "sha256": hashlib.sha256((root / relative).read_bytes()).hexdigest(),
                "result": "pass",
            }
            for index, relative in enumerate(objective_relatives)
        ]
        record = {
            "schemaVersion": 1,
            "scenario": scenario,
            "status": "PASS",
            "sourceCommit": source,
            "candidateJarSha256": jar,
            "serverVersion": version,
            "editions": list(contract.SCENARIO_REQUIRED_EDITIONS[scenario]),
            "checks": checks,
        }
        (root / record_relative).write_text(json.dumps(record), encoding="utf-8")
        scenario_claims[scenario]["evidence"] = [record_relative, *objective_relatives]
    (root / "SCENARIO_CLAIMS.json").write_text(
        json.dumps({"schemaVersion": 1, "scenarios": scenario_claims}),
        encoding="utf-8",
    )
    return source, jar, version


class ExactSmokeContractTest(unittest.TestCase):
    def test_release_workflow_scenario_identifiers_match_the_local_contract(self):
        workflow = (SCRIPTS.parent / ".github/workflows/release-smoke.yml").read_text(encoding="utf-8")
        step_marker = "      - name: Download and verify the immutable draft bytes\n"
        self.assertEqual(1, workflow.count(step_marker))
        release_step = workflow.split(step_marker, maxsplit=1)[1].split("\n  record:\n", maxsplit=1)[0]
        self.assertIn("jq -e --arg version", release_step)
        self.assertIn("' <<<\"$RESULTS_JSON\" >/dev/null", release_step)
        record_marker = "      - name: Create bounded machine-readable smoke record\n"
        self.assertEqual(1, workflow.count(record_marker))
        record_step = workflow.split(record_marker, maxsplit=1)[1].split("\n      - name: ", maxsplit=1)[0]
        self.assertIn("jq -ce '.' <<<\"$RESULTS_JSON\" > \"$RUNNER_TEMP/smoke-claims.json\"", record_step)
        match = re.search(
            r"\(\.scenarios \| keys \| sort\) == \[(.*?)\]\s+and\s+\(\[\.scenarios\[\]\]",
            release_step,
            flags=re.DOTALL,
        )
        self.assertIsNotNone(match, "release workflow scenario assertion was not found")
        scenario_array = match.group(1)
        workflow_scenarios = re.findall(r'^\s+"([A-Za-z][A-Za-z0-9]+)",?\s*$', scenario_array, flags=re.MULTILINE)
        self.assertEqual(len(contract.SMOKE_SCENARIO_KEYS), len(workflow_scenarios))
        self.assertEqual(sorted(contract.SMOKE_SCENARIO_KEYS), workflow_scenarios)
        self.assertEqual(",".join(f'\n              \"{key}\"' for key in workflow_scenarios), scenario_array.rstrip())

        publish = (SCRIPTS.parent / ".github/workflows/release-publish.yml").read_text(encoding="utf-8")
        publish_matches = list(
            re.finditer(
                r"\(\.scenarios \| keys \| sort\) == \[(.*?)\]\s+and\s+\(\[\.scenarios\[\]\]",
                publish,
                flags=re.DOTALL,
            )
        )
        self.assertEqual(4, len(publish_matches), "publication scenario assertions are missing or duplicated")
        for match in publish_matches:
            publish_scenarios = re.findall(r'"([A-Za-z][A-Za-z0-9]+)"', match.group(1))
            self.assertEqual(len(contract.SMOKE_SCENARIO_KEYS), len(publish_scenarios))
            self.assertEqual(sorted(contract.SMOKE_SCENARIO_KEYS), publish_scenarios)

        observation = (SCRIPTS.parent / ".github/workflows/release-rc-observation.yml").read_text(encoding="utf-8")
        observation_matches = list(
            re.finditer(
                r"\(\.scenarios \| keys \| sort\) == \[(.*?)\]\s+and\s+\(\[\.scenarios\[\]\]",
                observation,
                flags=re.DOTALL,
            )
        )
        self.assertEqual(1, len(observation_matches), "RC observation scenario assertion is missing or duplicated")
        observation_scenarios = re.findall(
            r'"([A-Za-z][A-Za-z0-9]+)"', observation_matches[0].group(1)
        )
        self.assertEqual(sorted(contract.SMOKE_SCENARIO_KEYS), observation_scenarios)

    def test_draft_release_readers_isolate_exact_ephemeral_permissions(self):
        def job_block(workflow: str, job_id: str) -> str:
            match = re.search(
                rf"^  {re.escape(job_id)}:\n(?P<body>.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)",
                workflow,
                flags=re.MULTILINE | re.DOTALL,
            )
            self.assertIsNotNone(match, f"missing workflow job: {job_id}")
            return match.group("body")

        def permission_map(job: str) -> dict[str, str]:
            match = re.search(r"^    permissions:(?P<inline> \{\})?\n", job, flags=re.MULTILINE)
            self.assertIsNotNone(match, "job must declare an explicit permission map")
            if match.group("inline"):
                return {}
            permissions = {}
            for line in job[match.end() :].splitlines():
                if not line.strip() or line.startswith("      #"):
                    continue
                item = re.fullmatch(r"      ([a-z-]+): (read|write|none)", line)
                if item is None:
                    break
                permissions[item.group(1)] = item.group(2)
            return permissions

        def assert_read_only_shell_boundary(job: str) -> None:
            self.assertEqual(1, len(re.findall(r"^      - name:", job, flags=re.MULTILINE)))
            self.assertNotRegex(job, r"(?m)^      - uses:")
            self.assertNotRegex(
                job,
                r"(?mi)\bgh\s+api\b[^\n]*(?:--method|-X)\s*(?:POST|PUT|PATCH|DELETE)\b",
            )
            self.assertNotRegex(job, r"(?mi)\bgh\s+release\s+(?:create|delete|edit|upload)\b")
            self.assertNotRegex(job, r"(?mi)\b(?:git\s+push|curl|wget)\b")

        smoke = (SCRIPTS.parent / ".github/workflows/release-smoke.yml").read_text(encoding="utf-8")
        validate_draft_job = job_block(smoke, "validate_draft")
        self.assertEqual({"contents": "write"}, permission_map(validate_draft_job))
        self.assertIn("GH_TOKEN: ${{ github.token }}", validate_draft_job)
        self.assertNotIn("secrets.", validate_draft_job)
        assert_read_only_shell_boundary(validate_draft_job)

        record_job = job_block(smoke, "record")
        self.assertEqual({}, permission_map(record_job))
        self.assertIn("    needs: validate_draft\n", record_job)
        self.assertNotIn("GH_TOKEN:", record_job)
        self.assertNotIn("secrets.", record_job)

        publish = (SCRIPTS.parent / ".github/workflows/release-publish.yml").read_text(encoding="utf-8")
        preflight_job = job_block(publish, "preflight")
        self.assertEqual(
            {"contents": "write", "actions": "read", "attestations": "read", "issues": "read"},
            permission_map(preflight_job),
        )
        self.assertIn("GH_TOKEN: ${{ github.token }}", preflight_job)
        self.assertNotIn("secrets.", preflight_job)
        assert_read_only_shell_boundary(preflight_job)
        self.assertEqual(2, publish.count("compare/$SOURCE_COMMIT...$GITHUB_SHA"))
        self.assertNotIn("compare/$SOURCE_COMMIT...main", publish)
        self.assertEqual(1, publish.count("secrets.IMMUTABLE_RELEASES_READ_TOKEN"))

    def test_rc_observation_and_stable_publication_are_structurally_fail_closed(self):
        def job_block(workflow: str, job_id: str) -> str:
            match = re.search(
                rf"^  {re.escape(job_id)}:\n(?P<body>.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)",
                workflow,
                flags=re.MULTILINE | re.DOTALL,
            )
            self.assertIsNotNone(match, f"missing workflow job: {job_id}")
            return match.group("body")

        def permission_map(job: str) -> dict[str, str]:
            match = re.search(r"^    permissions:(?P<inline> \{\})?\n", job, flags=re.MULTILINE)
            self.assertIsNotNone(match, "job must declare an explicit permission map")
            if match.group("inline"):
                return {}
            permissions = {}
            for line in job[match.end() :].splitlines():
                if not line.strip() or line.startswith("      #"):
                    continue
                item = re.fullmatch(r"      ([a-z-]+): (read|write|none)", line)
                if item is None:
                    break
                permissions[item.group(1)] = item.group(2)
            return permissions

        observation = (SCRIPTS.parent / ".github/workflows/release-rc-observation.yml").read_text(encoding="utf-8")
        self.assertIn("permissions: {}", observation)
        observe_job = job_block(observation, "observe")
        self.assertEqual(
            {"contents": "read", "actions": "read", "attestations": "read", "issues": "read"},
            permission_map(observe_job),
        )
        self.assertIn("ref: ${{ github.sha }}", observe_job)
        self.assertIn("persist-credentials: false", observe_job)
        self.assertIn("python3 scripts/rc_observation_contract.py", observe_job)
        self.assertNotIn("secrets.", observe_job)
        attest_job = job_block(observation, "attest")
        self.assertEqual({"id-token": "write", "attestations": "write"}, permission_map(attest_job))
        self.assertNotIn("actions/checkout", attest_job)
        self.assertNotIn("GH_TOKEN:", attest_job)
        self.assertNotIn("secrets.", attest_job)
        uses = re.findall(r"(?m)^\s+(?:- )?uses: ([^\s#]+)", observation)
        self.assertGreaterEqual(len(uses), 4)
        for action in uses:
            self.assertRegex(action, r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[a-f0-9]{40}$")

        publish = (SCRIPTS.parent / ".github/workflows/release-publish.yml").read_text(encoding="utf-8")
        publish_job = job_block(publish, "publish")
        self.assertEqual(
            {"contents": "write", "actions": "read", "attestations": "read", "issues": "read"},
            permission_map(publish_job),
        )
        self.assertEqual(
            2,
            publish.count('--signer-workflow "$GITHUB_REPOSITORY/.github/workflows/release-rc-observation.yml"'),
        )
        self.assertEqual(2, publish.count('(keys | sort) == ["baseVersion", "continuityChangedPaths"'))
        self.assertEqual(2, publish.count(".minimumObservationSeconds == 604800"))
        self.assertEqual(2, publish.count(".issueTriage.openReleaseBlockingP0 == 0"))
        self.assertEqual(2, publish.count(".issueTriage.globalOpenReleaseBlockingP0 == 0"))
        self.assertEqual(2, publish.count("issues?state=open&labels=gate%3Arelease-blocker"))
        self.assertEqual(2, publish.count("rc_publication_json=$(gh api"))
        self.assertEqual(2, publish.count("rc_smoke_json=$(gh api"))
        self.assertEqual(2, publish.count("--pattern independent-mcp-bridge-all.jar --pattern provenance.intoto.jsonl"))
        self.assertEqual(
            2,
            publish.count('validate_continuity "$OBSERVED_RC_SOURCE_COMMIT" "$observation_head"'),
        )
        self.assertEqual(2, publish.count('validate_continuity "$observation_head" "$SOURCE_COMMIT"'))
        self.assertEqual(2, publish.count("cmp \"$observation_dir/gradle.rc.normalized\""))
        self.assertEqual(2, publish.count("cmp \"$observation_dir/manifest.rc.normalized\""))
        self.assertEqual(2, publish.count("cmp \"$observation_dir/vulnerability-report.rc.normalized\""))
        self.assertEqual(2, publish.count('grep -Fx "# v$stable_version vulnerability review"'))
        self.assertEqual(2, publish.count('[[ -z "$RC_OBSERVATION_RUN_ID"'))
        self.assertEqual(2, publish.count('[[ "$RC_OBSERVATION_RUN_ID" =~ ^[1-9][0-9]*$ ]]'))
        self.assertEqual(2, publish.count('[[ "$GITHUB_SHA" == "$SOURCE_COMMIT" ]]'))
        self.assertEqual(2, publish.count(".draft == true and .prerelease == $prerelease"))
        self.assertEqual(2, publish.count(".draft == false and .prerelease == true and .immutable == true"))
        self.assertEqual(2, publish.count(".draft == false and .prerelease == $prerelease and .immutable == true"))

        smoke = (SCRIPTS.parent / ".github/workflows/release-smoke.yml").read_text(encoding="utf-8")
        draft = (SCRIPTS.parent / ".github/workflows/release-draft.yml").read_text(encoding="utf-8")
        self.assertEqual(1, smoke.count("V411_RELEASE_TAG=v4.11.0"))
        self.assertEqual(1, smoke.count("V411_RELEASE_REF=refs/heads/release/v4.11"))
        self.assertEqual(1, smoke.count("DEFAULT_REF=refs/heads/main"))
        self.assertIn('if [[ "$RELEASE_TAG" == "$V411_RELEASE_TAG" ]]; then', smoke)
        self.assertIn('[[ "$GITHUB_REF" == "$expected_workflow_ref" ]]', smoke)
        self.assertIn('[[ "$GITHUB_SHA" == "$SOURCE_COMMIT" ]]', smoke)

        self.assertEqual(1, draft.count("V411_RELEASE_TAG=v4.11.0"))
        self.assertEqual(1, draft.count("V411_RELEASE_BRANCH=release/v4.11"))
        self.assertEqual(1, draft.count("DEFAULT_BRANCH=main"))
        self.assertIn('[[ "$GITHUB_REF" == "refs/tags/$RELEASE_TAG" ]]', draft)
        self.assertIn('git fetch --no-tags origin "+refs/heads/$expected_ancestry_branch:$expected_ancestry_ref"', draft)
        self.assertIn('git merge-base --is-ancestor "$commit" "$expected_ancestry_ref"', draft)

        selector_pattern = re.compile(
            r"(?ms)^          V411_RELEASE_TAG=v4\.11\.0\n.*?^          fi"
            r"(?=\n          (?:\[\[|expected_ancestry_ref=))"
        )
        smoke_selectors = [textwrap.dedent(value) for value in selector_pattern.findall(smoke)]
        publish_selectors = [textwrap.dedent(value) for value in selector_pattern.findall(publish)]
        draft_selectors = [textwrap.dedent(value) for value in selector_pattern.findall(draft)]
        self.assertEqual(1, len(smoke_selectors))
        self.assertEqual(2, len(publish_selectors))
        self.assertEqual(publish_selectors[0], publish_selectors[1])
        self.assertEqual(1, len(draft_selectors))

        def assert_ref_matrix(
            selector: str,
            selected_variable: str,
            selected_branch_variable: str | None = None,
        ) -> None:
            for release_tag, github_ref, accepted in (
                ("v4.11.0", "refs/heads/release/v4.11", True),
                ("v4.11.0", "refs/heads/main", False),
                ("v4.11.0-rc.7", "refs/heads/main", True),
                ("v4.11.0-rc.7", "refs/heads/release/v4.11", False),
                ("v4.12.0-rc.1", "refs/heads/main", True),
            ):
                expected_branch = "release/v4.11" if release_tag == "v4.11.0" else "main"
                checks = [f'[[ "$GITHUB_REF" == "${selected_variable}" ]]']
                if selected_branch_variable is not None:
                    checks.append(f'[[ "${selected_branch_variable}" == "$EXPECTED_BRANCH" ]]')
                assertions = "\n" + " && ".join(checks) + "\n"
                result = subprocess.run(
                    ["bash", "-c", selector + assertions],
                    env={
                        **os.environ,
                        "RELEASE_TAG": release_tag,
                        "GITHUB_REF": github_ref,
                        "EXPECTED_BRANCH": expected_branch,
                    },
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(
                    accepted,
                    result.returncode == 0,
                    f"tag={release_tag} ref={github_ref} stderr={result.stderr!r}",
                )

        assert_ref_matrix(smoke_selectors[0], "expected_workflow_ref")
        for selector in publish_selectors:
            assert_ref_matrix(selector, "expected_workflow_ref", "expected_workflow_branch")

        for release_tag, expected_branch in (
            ("v4.11.0", "release/v4.11"),
            ("v4.11.0-rc.7", "main"),
            ("v4.12.0-rc.1", "main"),
        ):
            result = subprocess.run(
                ["bash", "-c", draft_selectors[0] + '\nprintf "%s" "$expected_ancestry_branch"\n'],
                env={**os.environ, "RELEASE_TAG": release_tag},
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual(expected_branch, result.stdout)

        self.assertEqual(2, publish.count("V411_RELEASE_TAG=v4.11.0"))
        self.assertEqual(2, publish.count("V411_RELEASE_BRANCH=release/v4.11"))
        self.assertEqual(2, publish.count("V411_RELEASE_REF=refs/heads/release/v4.11"))
        self.assertEqual(2, publish.count("DEFAULT_BRANCH=main"))
        self.assertEqual(2, publish.count("DEFAULT_REF=refs/heads/main"))
        self.assertEqual(2, publish.count('[[ "$GITHUB_REF" == "$expected_workflow_ref" ]]'))
        self.assertEqual(4, publish.count("expected_workflow_branch="))
        self.assertEqual(4, publish.count("expected_workflow_ref="))
        self.assertEqual(4, publish.count('.head_branch == $branch'))
        self.assertEqual(4, publish.count('--source-ref "$expected_workflow_ref"'))
        self.assertEqual(4, publish.count('.head_branch == "main"'))
        self.assertEqual(2, publish.count("--source-ref refs/heads/main"))
        self.assertEqual(2, publish.count('[[ "$OBSERVED_RC_TAG" == "$V411_RC_TAG" ]]'))
        self.assertEqual(2, publish.count('[[ "$OBSERVED_RC_SOURCE_COMMIT" == "$V411_RC_SOURCE_SHA" ]]'))

        self.assertIn("V411_RELEASE_REF: refs/heads/release/v4.11", observation)
        self.assertIn("V411_RC_TAG: v4.11.0-rc.7", observation)
        self.assertIn("V411_RC_SOURCE_SHA: 3eb0ff3bab614c1fe173b1c95c11dd5c3ee48121", observation)
        self.assertIn('[[ "$GITHUB_REF" == "$V411_RELEASE_REF" ]]', observation)
        self.assertEqual(2, observation.count('.head_branch == "main"'))
        self.assertEqual(1, observation.count("--source-ref refs/heads/main"))

        def workflow_dispatch_inputs(workflow: str) -> set[str]:
            self.assertEqual(1, workflow.count("    inputs:\n"))
            body = workflow.split("    inputs:\n", maxsplit=1)[1].split("\npermissions:", maxsplit=1)[0]
            return set(re.findall(r"(?m)^      ([A-Za-z_][A-Za-z0-9_-]*):$", body))

        self.assertEqual({"tag", "source_sha"}, workflow_dispatch_inputs(draft))
        self.assertEqual(
            {
                "tag",
                "source_sha",
                "tested_jar_sha256",
                "operating_systems",
                "burp_community_version",
                "burp_professional_version",
                "mcp_clients",
                "results_json",
            },
            workflow_dispatch_inputs(smoke),
        )
        self.assertEqual(
            {
                "tag",
                "source_sha",
                "smoke_run_id",
                "rc_observation_run_id",
                "observed_rc_tag",
                "observed_rc_source_sha",
            },
            workflow_dispatch_inputs(publish),
        )
        self.assertEqual(
            {"rc_tag", "rc_source_sha", "protected_smoke_run_id", "publication_run_id"},
            workflow_dispatch_inputs(observation),
        )
        self.assertNotIn("Stable publication remains blocked until", publish)

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
        self.assertEqual(11, summary["NOT RUN"])
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
        self.assertEqual(11, len(workflow["scenarios"]))
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

        for retired in ("dataApprovalAndProjectTransition", "scopeScannerUncertainOutcomes"):
            self.assertNotIn(retired, contract.SMOKE_SCENARIO_KEYS)
            extra = claims()
            extra[retired] = {
                "status": "NOT RUN",
                "evidence": [],
                "notes": "Retired from the release smoke contract.",
            }
            with self.assertRaises(HarnessError):
                contract.validate_scenario_claims(extra)

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
                    "--community-lifecycle-report", "evidence/community-bearer-lifecycle.json",
                    "--professional-lifecycle-report", "evidence/professional-bearer-lifecycle.json",
                    "--scenario-claims", claims_file,
                    "--candidate-jar", "assets/candidate.jar",
                    "--expected-jar-sha256", jar,
                    "--expected-source-commit", source,
                    "--expected-server-version", version,
                    "--forbidden-value-file", str(root / "private-forbidden-value"),
                    *lifecycle_token_arguments(root),
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
            self.assertEqual(
                {
                    "community": {
                        "crossEditionIsolationConfirmed": True,
                        "projectSwitchStable": True,
                        "restartStable": True,
                        "rotationChanged": True,
                        "projectSwitchAuthenticated": True,
                        "restartAuthenticated": True,
                        "listenerStartupTokenRetained": True,
                        "rotationCutoverAuthenticated": True,
                        "secondRestartStable": True,
                    },
                    "professional": {
                        "crossEditionIsolationConfirmed": True,
                        "projectSwitchStable": True,
                        "restartStable": True,
                        "rotationChanged": True,
                        "projectSwitchAuthenticated": True,
                        "restartAuthenticated": True,
                        "listenerStartupTokenRetained": True,
                        "rotationCutoverAuthenticated": True,
                        "secondRestartStable": True,
                    },
                },
                matrix["credentialLifecycle"],
            )
            self.assertEqual(11, len(workflow["scenarios"]))
            self.assertEqual(0o600, stat.S_IMODE((root / "MATRIX.json").stat().st_mode))
            self.assertEqual(0o600, stat.S_IMODE((root / "WORKFLOW.json").stat().st_mode))

            withheld = json.loads((root / "SCENARIO_CLAIMS.json").read_text(encoding="utf-8"))
            blocked_key = "boundedLargeDataAndCancellation"
            withheld["scenarios"][blocked_key] = {
                "status": "BLOCKED",
                "evidence": [],
                "notes": "Required evidence is unavailable.",
            }
            (root / "WITHHELD_CLAIMS.json").write_text(json.dumps(withheld), encoding="utf-8")
            self.assertEqual(1, invoke("WITHHELD_CLAIMS.json", "WITHHELD_MATRIX.json", "ABSENT_WORKFLOW.json"))
            withheld_matrix = json.loads((root / "WITHHELD_MATRIX.json").read_text(encoding="utf-8"))
            self.assertFalse(withheld_matrix["summary"]["protectedSmokeEligible"])
            self.assertEqual("WITHHOLD", withheld_matrix["releaseDisposition"])
            self.assertFalse((root / "ABSENT_WORKFLOW.json").exists())

    def test_finalizer_requires_distinct_stable_then_rotated_private_tokens_for_both_editions(self):
        finalizer = load_finalizer_module()
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            build_finalizer_fixture(root)
            paths = {
                edition: {
                    "beforeProjectSwitch": root / f"private-{edition}-token-before-project-switch",
                    "afterProjectSwitch": root / f"private-{edition}-token-after-project-switch",
                    "afterRestart": root / f"private-{edition}-token-after-restart",
                    "afterRotation": root / f"private-{edition}-token-after-rotation",
                }
                for edition in ("community", "professional")
            }

            summary, values = finalizer.validate_lifecycle_token_files(paths)
            self.assertTrue(summary["community"]["projectSwitchStable"])
            self.assertTrue(summary["professional"]["restartStable"])
            self.assertEqual(8, len(values))

            paths["community"]["afterProjectSwitch"].write_text("x" * 43, encoding="utf-8")
            with self.assertRaises(HarnessError):
                finalizer.validate_lifecycle_token_files(paths)
            paths["community"]["afterProjectSwitch"].write_text("c" * 43, encoding="utf-8")

            paths["community"]["afterRestart"].write_text("x" * 43, encoding="utf-8")
            with self.assertRaises(HarnessError):
                finalizer.validate_lifecycle_token_files(paths)
            paths["community"]["afterRestart"].write_text("c" * 43, encoding="utf-8")

            paths["community"]["afterRotation"].write_text("c" * 43, encoding="utf-8")
            with self.assertRaises(HarnessError):
                finalizer.validate_lifecycle_token_files(paths)
            paths["community"]["afterRotation"].write_text("d" * 43, encoding="utf-8")

            for stage in ("beforeProjectSwitch", "afterProjectSwitch", "afterRestart"):
                paths["professional"][stage].write_text("c" * 43, encoding="utf-8")
            paths["professional"]["afterRotation"].write_text("d" * 43, encoding="utf-8")
            with self.assertRaises(HarnessError):
                finalizer.validate_lifecycle_token_files(paths)
            for stage in ("beforeProjectSwitch", "afterProjectSwitch", "afterRestart"):
                paths["professional"][stage].write_text("p" * 43, encoding="utf-8")
            paths["professional"]["afterRotation"].write_text("r" * 43, encoding="utf-8")

            duplicate = paths["professional"]["afterRestart"]
            duplicate.unlink()
            duplicate.hardlink_to(paths["professional"]["afterProjectSwitch"])
            with self.assertRaises(HarnessError):
                finalizer.validate_lifecycle_token_files(paths)

    def test_lifecycle_report_requires_exact_candidate_bound_ordered_authentication_events(self):
        finalizer = load_finalizer_module()
        source = "a" * 40
        jar = "b" * 64
        version = "4.11.0-rc.7"
        report = lifecycle_report("community", source, jar, version)

        summary = finalizer.validate_lifecycle_report(report, "community", source, jar, version)
        self.assertTrue(summary["rotationCutoverAuthenticated"])
        self.assertTrue(summary["secondRestartStable"])

        report["crossEditionIsolation"]["separateDataDirectory"] = False
        with self.assertRaises(HarnessError):
            finalizer.validate_lifecycle_report(report, "community", source, jar, version)
        report["crossEditionIsolation"]["separateDataDirectory"] = True
        report["events"][1]["differentProjectOpened"] = False
        with self.assertRaises(HarnessError):
            finalizer.validate_lifecycle_report(report, "community", source, jar, version)
        report["events"][1]["differentProjectOpened"] = True
        report["events"][5]["oldTokenRejected401"] = 1
        with self.assertRaises(HarnessError):
            finalizer.validate_lifecycle_report(report, "community", source, jar, version)
        report["events"][5]["oldTokenRejected401"] = True
        report["events"][6]["oldTokenRejected401"] = False
        with self.assertRaises(HarnessError):
            finalizer.validate_lifecycle_report(report, "community", source, jar, version)

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
                "--community-lifecycle-report", "evidence/community-bearer-lifecycle.json",
                "--professional-lifecycle-report", "evidence/professional-bearer-lifecycle.json",
                "--scenario-claims", "SCENARIO_CLAIMS.json",
                "--candidate-jar", "assets/candidate.jar",
                "--expected-jar-sha256", jar,
                "--expected-source-commit", source,
                "--expected-server-version", version,
                "--forbidden-value-file", str(root / "private-forbidden-value"),
                *lifecycle_token_arguments(root),
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
            r'{"bearer\u0054oken":"private-value"}',
            r'{"client\u0053ecret":"private-value"}',
            r'{"o\u0061uth_token":"private-value"}',
            r'{"secret\u004bey":"private-value"}',
            r'{"x-api-key":"private-value"}',
        )
        bad_values = (
            b'{"value":"private-marker"}\n',
            b'{"projectId":"opaque"}\n',
            b'{"stable-id":"opaque"}\n',
            b'{"stable_id":"opaque"}\n',
            b'{"stable.id":"opaque"}\n',
            b'{"stable id":"opaque"}\n',
            b'{"scanner.task-id":"opaque"}\n',
            b'{"collaborator_payload":"opaque"}\n',
            b'prefix "stableId": opaque\n',
            b'prefix stableId: opaque\n',
            b'stableId: opaque\n',
            b'session_id: opaque\n',
            b'prefix "token": false\n',
            b"prefix {'client_secret': null}\n",
            b'prefix "stable/id": opaque\n',
            b"prefix 'client/secret': null\n",
            'prefix "stable\u200bid": opaque\n'.encode("utf-8"),
            'prefix "ſtableId": opaque\n'.encode("utf-8"),
            b'prefix stable\tid: opaque\n',
            json.dumps({"log": 'prefix "token": false'}).encode("utf-8"),
            json.dumps({"log": 'prefix "stable/id": opaque'}).encode("utf-8"),
            json.dumps({"log": 'prefix "client/secret": null'}).encode("utf-8"),
            b'{"value":"123e4567-e89b-12d3-a456-426614174000"}\n',
            b'Authorization: Bearer redacted\n',
            b'{"Authorization":"Bearer redacted"}\n',
            b'{"token":"private-value"}\n',
            b'{"bearerToken":"private-value"}\n',
            b'{"access_token":"private-value"}\n',
            b'{"authToken":"private-value"}\n',
            b'{"apiToken":"private-value"}\n',
            b'{"oauth_token":"private-value"}\n',
            b'{"id.token":"private-value"}\n',
            b'{"client_secret":"private-value"}\n',
            b'{"password":"private-value"}\n',
            b'{"credentials":{"kind":"private"}}\n',
            b'{"x_api_key":"private-value"}\n',
            b'{"privateKey":"private-value"}\n',
            b'{"secretKey":"private-value"}\n',
            b'{"passwd":"private-value"}\n',
            b'{"jwt":"private-value"}\n',
            b'{"token":false}\n',
            b'client-secret: private-value\n',
            b'oauth.token: private-value\n',
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
            for structural_value in (
                b'{"stableId":"opaque"}',
                b'{"stable-id":"opaque"}',
                b'{"scanner.task-id":"opaque"}',
                b'{"collaborator_payload":"opaque"}',
                b'{"token":false}',
                b'bearer-token: null',
            ):
                with self.assertRaises(HarnessError):
                    contract.validate_permanent_text(structural_value, ())
            for escaped_value, forbidden_value in (
                (b'prefix "value":"private\\ud83d\\ude00"', "private😀".encode("utf-8")),
                (b'prefix "value":"private\\/value"', b"private/value"),
                (b'prefix \\"token\\": false', b"unrelated-private-value"),
            ):
                with self.assertRaises(HarnessError):
                    contract.validate_permanent_text(escaped_value, (forbidden_value,))
            escaped_forbidden_key = json.dumps({"private😀": "value"}).encode("utf-8")
            with self.assertRaises(HarnessError):
                contract.validate_permanent_text(escaped_forbidden_key, ("private😀".encode("utf-8"),))
            good = root / "good.json"
            good.write_text(
                json.dumps({
                    "projectIdentifierRecorded": False,
                    "tokenRecorded": False,
                    "cursorAndStableId": {"pagesDisjoint": True, "rawIdentifiersRecorded": False},
                    "cursor_stable_id": "categorical-check-name",
                    "cursor stableId": "categorical-check-name",
                    "cursor/stableId": "categorical-check-name",
                    "cursor\u200bstableId": "categorical-check-name",
                    "cursorſtableId": "categorical-check-name",
                    "stableReferenceIdentifierPresent": True,
                    "nestedReport": json.dumps({
                        "cursorAndStableId": {"stableReferenceResolved": True},
                    }),
                    "status": "passed",
                }) + "\n",
                encoding="utf-8",
            )
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
