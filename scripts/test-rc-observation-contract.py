#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import json
import pathlib
import re
import shlex
import subprocess
import tempfile
import unittest
from unittest import mock

SCRIPTS = pathlib.Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("rc_observation_contract", SCRIPTS / "rc_observation_contract.py")
contract = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(contract)


class RcObservationContractTest(unittest.TestCase):
    def labels(self) -> list[dict[str, str]]:
        return [{"name": name} for name in contract.REQUIRED_LABELS]

    def issue(
        self,
        number: int = 1,
        *,
        state: str = "open",
        priority: str = "priority:P2",
        gate: str = "gate:non-blocking",
        created_at: str = "2026-08-01T00:00:00Z",
    ) -> dict:
        return {
            "number": number,
            "state": state,
            "created_at": created_at,
            "labels": [{"name": priority}, {"name": gate}],
        }

    def arguments(self, **overrides):
        values = {
            "repository": "sehoon123/mcp-server",
            "rc_tag": "v4.11.0-rc.7",
            "rc_source_commit": "a" * 40,
            "rc_release_id": 123,
            "rc_jar_sha256": "b" * 64,
            "rc_asset_snapshot_sha256": "d" * 64,
            "rc_published_at": "2026-07-31T15:32:22Z",
            "observed_at": "2026-08-07T15:32:22Z",
            "protected_smoke_run": 456,
            "publication_run": 789,
            "observation_workflow_run": 1011,
            "observation_workflow_commit": "c" * 40,
            "observer_actor": "sehoon123",
            "authorized_actor": "sehoon123",
            "repository_json": {
                "full_name": "sehoon123/mcp-server",
                "has_issues": True,
                "archived": False,
                "disabled": False,
            },
            "compare_json": {
                "status": "ahead",
                "ahead_by": 1,
                "behind_by": 0,
                "merge_base_commit": {"sha": "a" * 40},
                "files": [
                    {"filename": path}
                    for path in sorted(contract.OBSERVATION_CONTINUITY_PATHS)
                ],
            },
            "labels": self.labels(),
            "issues": [],
            "open_blockers": [],
        }
        values.update(overrides)
        return values

    def test_exact_seven_day_observation_produces_bounded_record(self):
        record = contract.build_observation_record(**self.arguments())
        self.assertEqual(1, record["schemaVersion"])
        self.assertEqual("4.11.0", record["baseVersion"])
        self.assertEqual(604_800, record["minimumObservationSeconds"])
        self.assertEqual(604_800, record["elapsedSeconds"])
        self.assertTrue(record["eligibleForStable"])
        self.assertEqual([], record["issueTriage"]["triagedIssueNumbers"])
        self.assertEqual([], record["issueTriage"]["globalOpenBlockerIssueNumbers"])
        self.assertEqual(
            "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
            record["issueTriage"]["snapshotSha256"],
        )
        self.assertEqual(sorted(contract.REQUIRED_LABELS), record["requiredLabels"])
        self.assertEqual(sorted(contract.OBSERVATION_CONTINUITY_PATHS), record["continuityChangedPaths"])
        self.assertEqual("d" * 64, record["rcAssetSnapshotSha256"])

    def test_observation_fails_before_full_seven_days(self):
        with self.assertRaisesRegex(contract.ContractError, "observation window"):
            contract.build_observation_record(
                **self.arguments(observed_at="2026-08-07T15:32:21Z")
            )

    def test_required_label_inventory_is_fail_closed(self):
        labels = self.labels()[:-1]
        with self.assertRaisesRegex(contract.ContractError, "labels are missing"):
            contract.build_observation_record(**self.arguments(labels=labels))
        with self.assertRaisesRegex(contract.ContractError, "duplicate"):
            contract.build_observation_record(**self.arguments(labels=self.labels() + [self.labels()[0]]))

    def test_every_issue_created_during_window_requires_exact_triage(self):
        for labels in (
            [],
            [{"name": "priority:P2"}],
            [{"name": "gate:non-blocking"}],
            [
                {"name": "priority:P1"},
                {"name": "priority:P2"},
                {"name": "gate:non-blocking"},
            ],
            [
                {"name": "priority:P2"},
                {"name": "gate:non-blocking"},
                {"name": "gate:release-blocker"},
            ],
        ):
            issue = self.issue()
            issue["labels"] = labels
            with self.assertRaises(contract.ContractError):
                contract.build_observation_record(**self.arguments(issues=[issue]))

    def test_open_release_blocking_p0_or_p1_fails(self):
        for priority in ("priority:P0", "priority:P1"):
            issue = self.issue(priority=priority, gate="gate:release-blocker")
            with self.assertRaisesRegex(contract.ContractError, "unresolved release-blocking"):
                contract.build_observation_record(**self.arguments(issues=[issue]))

    def test_closed_blocker_and_open_p2_are_recorded_but_do_not_block(self):
        issues = [
            self.issue(1, state="closed", priority="priority:P0", gate="gate:release-blocker"),
            self.issue(2, state="open", priority="priority:P2", gate="gate:release-blocker"),
            self.issue(3, state="open", priority="priority:P1", gate="gate:non-blocking"),
        ]
        record = contract.build_observation_record(**self.arguments(issues=issues))
        self.assertEqual([1, 2, 3], record["issueTriage"]["triagedIssueNumbers"])
        self.assertEqual(0, record["issueTriage"]["openReleaseBlockingP0"])
        self.assertEqual(0, record["issueTriage"]["openReleaseBlockingP1"])

    def test_preexisting_global_open_p0_or_p1_blocker_fails(self):
        for priority in ("priority:P0", "priority:P1"):
            blocker = self.issue(
                priority=priority,
                gate="gate:release-blocker",
                created_at="2026-07-01T00:00:00Z",
            )
            with self.assertRaisesRegex(contract.ContractError, "global unresolved"):
                contract.build_observation_record(**self.arguments(open_blockers=[blocker]))

        p2 = self.issue(
            priority="priority:P2",
            gate="gate:release-blocker",
            created_at="2026-07-01T00:00:00Z",
        )
        record = contract.build_observation_record(**self.arguments(open_blockers=[p2]))
        self.assertEqual([1], record["issueTriage"]["globalOpenBlockerIssueNumbers"])

    def test_pull_requests_and_out_of_window_issues_are_not_part_of_snapshot(self):
        pull_request = self.issue(1, priority="priority:P0", gate="gate:release-blocker")
        pull_request["pull_request"] = {"url": "https://example.invalid"}
        before = self.issue(2, created_at="2026-07-31T15:32:21Z")
        after = self.issue(3, created_at="2026-08-07T15:32:23Z")
        record = contract.build_observation_record(
            **self.arguments(issues=[pull_request, before, after])
        )
        self.assertEqual([], record["issueTriage"]["triagedIssueNumbers"])

    def test_repository_and_continuity_are_fail_closed(self):
        repository = dict(self.arguments()["repository_json"])
        repository["has_issues"] = False
        with self.assertRaisesRegex(contract.ContractError, "Issues must be enabled"):
            contract.build_observation_record(**self.arguments(repository_json=repository))

        valid_compare = self.arguments()["compare_json"]
        invalid_comparisons = (
            {**valid_compare, "status": "diverged", "behind_by": 1},
            {**valid_compare, "status": "behind", "behind_by": 1},
            {**valid_compare, "merge_base_commit": {"sha": "e" * 40}},
            {**valid_compare, "files": []},
            {**valid_compare, "files": [*valid_compare["files"], {"filename": "src/main/kotlin/Runtime.kt"}]},
            {**valid_compare, "files": [{"filename": "docs/RELEASING.md", "previous_filename": "src/main/kotlin/Runtime.kt"}, *valid_compare["files"][1:]]},
            {**valid_compare, "files": [*valid_compare["files"], valid_compare["files"][0]]},
            {**valid_compare, "files": valid_compare["files"][:-1]},
            {
                **valid_compare,
                "files": [
                    entry for entry in valid_compare["files"]
                    if entry["filename"] != ".github/workflows/release-smoke.yml"
                ],
            },
        )
        for compare in invalid_comparisons:
            with self.subTest(compare=compare), self.assertRaises(contract.ContractError):
                contract.build_observation_record(**self.arguments(compare_json=compare))

        record = contract.build_observation_record(**self.arguments(compare_json=valid_compare))
        self.assertEqual(sorted(contract.OBSERVATION_CONTINUITY_PATHS), record["continuityChangedPaths"])

    def test_issue_queries_are_bounded_after_relevance_filtering(self):
        relevant = [self.issue(number, created_at="2026-08-01T00:00:00Z") for number in range(1, 1002)]
        with self.assertRaisesRegex(contract.ContractError, "bounded observation limit"):
            contract.build_observation_record(**self.arguments(issues=relevant))

        older = [self.issue(number, created_at="2026-07-01T00:00:00Z") for number in range(1, 1002)]
        record = contract.build_observation_record(**self.arguments(issues=older))
        self.assertEqual(0, record["issueTriage"]["observedIssueCount"])

        p2_blockers = [
            self.issue(number, priority="priority:P2", gate="gate:release-blocker")
            for number in range(1, 1002)
        ]
        with self.assertRaisesRegex(contract.ContractError, "global blocker query exceeded"):
            contract.build_observation_record(**self.arguments(open_blockers=p2_blockers))

    def test_identity_timestamp_and_actor_fields_are_strict(self):
        invalid = (
            {"rc_tag": "v4.11.0"},
            {"rc_tag": "v4.11.0-rc.01"},
            {"rc_source_commit": "A" * 40},
            {"rc_jar_sha256": "b" * 63},
            {"rc_asset_snapshot_sha256": "d" * 63},
            {"observation_workflow_commit": "C" * 40},
            {"rc_release_id": True},
            {"rc_published_at": "2026-07-31 15:32:22Z"},
            {"repository": "other/repository"},
            {"observer_actor": "other"},
        )
        for replacement in invalid:
            with self.subTest(replacement=replacement), self.assertRaises(contract.ContractError):
                contract.build_observation_record(**self.arguments(**replacement))

    def test_workflow_copies_contract_constants_without_runtime_paths(self):
        publish = (SCRIPTS.parent / ".github/workflows/release-publish.yml").read_text(encoding="utf-8")
        observation = (SCRIPTS.parent / ".github/workflows/release-rc-observation.yml").read_text(encoding="utf-8")
        def copied_path_sets(variable: str) -> list[list[str]]:
            matches = re.findall(
                rf"{variable}=\$\(printf '%s\\n' (.*?) \| LC_ALL=C sort \|",
                publish,
                flags=re.DOTALL,
            )
            self.assertEqual(2, len(matches), variable)
            return [sorted(shlex.split(match.replace("\\\n", " "))) for match in matches]

        expected_observation = sorted(contract.OBSERVATION_CONTINUITY_PATHS)
        expected_stable = sorted(
            [*contract.STABLE_PROMOTION_FIXED_PATHS, "docs/releases/$stable_version.md"]
        )
        for copied in copied_path_sets("observation_paths"):
            self.assertEqual(expected_observation, copied)
        for copied in copied_path_sets("stable_paths"):
            self.assertEqual(expected_stable, copied)
        for label in contract.REQUIRED_LABELS:
            self.assertGreaterEqual(publish.count(label), 4, label)
        self.assertIn("python3 scripts/rc_observation_contract.py", observation)
        self.assertIn("V411_RELEASE_REF: refs/heads/release/v4.11", observation)
        self.assertIn("V411_RC_TAG: v4.11.0-rc.7", observation)
        self.assertIn(
            "V411_RC_SOURCE_SHA: 3eb0ff3bab614c1fe173b1c95c11dd5c3ee48121",
            observation,
        )
        self.assertIn('[[ "$GITHUB_REF" == "$V411_RELEASE_REF" ]]', observation)
        self.assertIn('[[ "$RC_TAG" == "$V411_RC_TAG" && "$RC_SOURCE_COMMIT" == "$V411_RC_SOURCE_SHA" ]]', observation)
        self.assertEqual(2, observation.count('.head_branch == "main"'))
        self.assertEqual(1, observation.count("--source-ref refs/heads/main"))
        self.assertEqual(1, observation.count("issues?state=open&labels=gate%3Arelease-blocker"))
        self.assertIn('--open-blockers-json "$open_blockers_json"', observation)
        self.assertEqual(2, publish.count("V411_RELEASE_BRANCH=release/v4.11"))
        self.assertEqual(2, publish.count("V411_RC_TAG=v4.11.0-rc.7"))
        self.assertEqual(
            2,
            publish.count("V411_RC_SOURCE_SHA=3eb0ff3bab614c1fe173b1c95c11dd5c3ee48121"),
        )
        self.assertEqual(4, publish.count('--arg branch "$expected_workflow_branch"'))
        self.assertEqual(4, publish.count('--source-ref "$expected_workflow_ref"'))
        self.assertEqual(4, publish.count('.head_branch == "main"'))
        self.assertEqual(2, publish.count("--source-ref refs/heads/main"))
        self.assertEqual(604_800, contract.MINIMUM_OBSERVATION_SECONDS)
        self.assertEqual(2, publish.count(".minimumObservationSeconds == 604800"))

        jq_programs = re.findall(
            r"jq -e --arg base \"\$base\" --argjson expected \"\$expected\" '(.*?)' \"\$output\"",
            publish,
            flags=re.DOTALL,
        )
        self.assertEqual(2, len(jq_programs))
        self.assertEqual(jq_programs[0], jq_programs[1])
        base = "a" * 40
        expected = expected_observation
        valid_compare = {
            "merge_base_commit": {"sha": base},
            "status": "ahead",
            "behind_by": 0,
            "files": [{"filename": path} for path in expected],
        }

        def jq_accepts(value: dict) -> bool:
            result = subprocess.run(
                ["jq", "-e", "--arg", "base", base, "--argjson", "expected", json.dumps(expected), jq_programs[0]],
                input=json.dumps(value),
                text=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
            return result.returncode == 0

        self.assertTrue(jq_accepts(valid_compare))
        self.assertFalse(
            jq_accepts(
                {**valid_compare, "files": [*valid_compare["files"], {"filename": "src/main/kotlin/Runtime.kt"}]}
            )
        )
        renamed = json.loads(json.dumps(valid_compare))
        renamed["files"][0]["previous_filename"] = "src/main/kotlin/Runtime.kt"
        self.assertFalse(jq_accepts(renamed))

    def test_publish_record_and_issue_jq_contracts_execute_on_fixtures(self):
        publish = (SCRIPTS.parent / ".github/workflows/release-publish.yml").read_text(encoding="utf-8")

        def programs_for(filename: str) -> list[str]:
            end_marker = f'\n            \' "$observation_dir/{filename}.json" >/dev/null'
            programs: list[str] = []
            offset = 0
            while True:
                end = publish.find(end_marker, offset)
                if end < 0:
                    break
                start_marker = "            jq -e '\n"
                start = publish.rfind(start_marker, 0, end)
                self.assertGreaterEqual(start, 0)
                programs.append(publish[start + len(start_marker) : end])
                offset = end + len(end_marker)
            self.assertEqual(2, len(programs), filename)
            self.assertEqual(programs[0], programs[1])
            return programs

        def jq_accepts(program: str, value: object, arguments: list[str] | None = None) -> bool:
            command = ["jq", "-e", *(arguments or []), program]
            result = subprocess.run(
                command,
                input=json.dumps(value),
                text=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
            return result.returncode == 0

        window_program = programs_for("issues")[0]
        self.assertTrue(jq_accepts(window_program, []))
        self.assertTrue(jq_accepts(window_program, [self.issue(priority="priority:P2", gate="gate:release-blocker")]))
        self.assertFalse(jq_accepts(window_program, [self.issue(priority="priority:P1", gate="gate:release-blocker")]))
        untriaged = self.issue()
        untriaged["labels"] = []
        self.assertFalse(jq_accepts(window_program, [untriaged]))

        blocker_program = programs_for("open-blockers")[0]
        self.assertTrue(jq_accepts(blocker_program, []))
        self.assertTrue(jq_accepts(blocker_program, [self.issue(priority="priority:P2", gate="gate:release-blocker")]))
        self.assertFalse(jq_accepts(blocker_program, [self.issue(priority="priority:P0", gate="gate:release-blocker")]))
        contradictory = self.issue(priority="priority:P2", gate="gate:release-blocker")
        contradictory["labels"].append({"name": "gate:non-blocking"})
        self.assertFalse(jq_accepts(blocker_program, [contradictory]))

        record_programs = re.findall(
            r'--argjson observationRun "\$RC_OBSERVATION_RUN_ID" --arg stableJar "\$stable_jar_sha" \'(.*?)\'\s+"\$observation_record"',
            publish,
            flags=re.DOTALL,
        )
        self.assertEqual(2, len(record_programs))
        self.assertEqual(record_programs[0], record_programs[1])
        record = contract.build_observation_record(**self.arguments())
        record_arguments = [
            "--arg", "repo", "sehoon123/mcp-server",
            "--arg", "rcTag", "v4.11.0-rc.7",
            "--arg", "rcSha", "a" * 40,
            "--arg", "version", "4.11.0",
            "--arg", "actor", "sehoon123",
            "--arg", "observationHead", "c" * 40,
            "--argjson", "observationRun", "1011",
            "--arg", "stableJar", "e" * 64,
        ]
        self.assertTrue(jq_accepts(record_programs[0], record, record_arguments))
        self.assertFalse(jq_accepts(record_programs[0], {**record, "extra": True}, record_arguments))
        self.assertFalse(
            jq_accepts(record_programs[0], {**record, "baseVersion": "4.12.0"}, record_arguments)
        )

    def test_cli_creates_mode_0600_record_once(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            labels = root / "labels.json"
            issues = root / "issues.json"
            repository = root / "repository.json"
            compare = root / "compare.json"
            open_blockers = root / "open-blockers.json"
            output = root / "observation.json"
            labels.write_text(json.dumps(self.labels()), encoding="utf-8")
            issues.write_text("[]", encoding="utf-8")
            open_blockers.write_text("[]", encoding="utf-8")
            repository.write_text(json.dumps(self.arguments()["repository_json"]), encoding="utf-8")
            compare.write_text(json.dumps(self.arguments()["compare_json"]), encoding="utf-8")
            argv = [
                "rc_observation_contract.py",
                "--repository", "sehoon123/mcp-server",
                "--rc-tag", "v4.11.0-rc.7",
                "--rc-source-commit", "a" * 40,
                "--rc-release-id", "123",
                "--rc-jar-sha256", "b" * 64,
                "--rc-asset-snapshot-sha256", "d" * 64,
                "--rc-published-at", "2026-07-31T15:32:22Z",
                "--observed-at", "2026-08-07T15:32:22Z",
                "--protected-smoke-run", "456",
                "--publication-run", "789",
                "--observation-workflow-run", "1011",
                "--observation-workflow-commit", "c" * 40,
                "--observer-actor", "sehoon123",
                "--authorized-actor", "sehoon123",
                "--repository-json", str(repository),
                "--compare-json", str(compare),
                "--labels-json", str(labels),
                "--issues-json", str(issues),
                "--open-blockers-json", str(open_blockers),
                "--output", str(output),
            ]
            with mock.patch("sys.argv", argv):
                self.assertEqual(0, contract.main())
            self.assertEqual(0o600, output.stat().st_mode & 0o777)
            with mock.patch("sys.argv", argv), self.assertRaises(FileExistsError):
                contract.main()


if __name__ == "__main__":
    unittest.main()
