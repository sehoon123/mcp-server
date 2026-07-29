# Exact-byte Burp smoke harness

This document defines the repository-supported local evidence helpers for a **future** release candidate. The helpers are
part of the candidate source identity: run them only from the clean commit named by `--expected-source-commit`. They do
not retroactively change or validate an immutable earlier tag, draft, asset, or release candidate. In particular, they
must not be used to rewrite the `v4.11.0-rc.1` or `v4.11.0-rc.2` records.

The current implementation is a fail-closed orchestration slice, not unattended Burp automation. It validates one live
edition at a time, provides a deterministic diagnostics barrier for caller-disconnect cancellation, and finalizes two
edition reports plus operator-reviewed scenario evidence. It does **not** launch Burp, accept a license, copy a license or
bearer, create/replace a project, click approval dialogs, unload/reload the extension, or trigger a project transition.
Those actions require a separately reviewed guarded UI driver or operator workflow and objective post-action checks.

## Safety and evidence boundary

Run in a trusted local account and filesystem. The harness treats authenticated MCP clients as hostile, but it is not a
sandbox against another same-user process rewriting the candidate JAR, evidence root, checkout, token, or Burp data while
the run is active. Any concurrent filesystem mutation invalidates the evidence and must fail the operator review.

Use a disposable Burp data directory and a fresh temporary project for each edition. Do not copy a Professional license
into evidence or command-line arguments. Load the exact downloaded JAR, verify its digest before launch, and copy the
current extension-lifetime bearer into a new mode-0600 file only after that load or restart. Keep bearer, project/session
identifiers, stable references, traffic, Scanner task IDs, Collaborator payloads, and approval markers in private scratch
or memory.

Every runner requires:

- an explicit disposable-project acknowledgement;
- a clean checkout at the exact full source commit;
- the exact regular non-symlink candidate JAR and expected SHA-256;
- a loopback `/mcp` endpoint and current mode-0600 bearer file;
- a live Burp PID and bounded whole-process RSS limit; and
- a new private output path.

Reports contain only bounded aggregate state. A timeout, `Ctrl-C`, missing report, completed-before-barrier call, failed
precondition, `BLOCKED`, or `NOT RUN` result is never promoted to `PASS`. The finalizer rejects symlink/path traversal,
non-canonical path spellings, physical-file aliases, UUID-shaped values, decoded private/credential JSON keys (including
BOM-aware UTF-8/16/32, Unicode escapes, and bounded nested JSON text), credential-bearing text under any file suffix, and
exact forbidden runtime values in permanent evidence. JSON-looking text is lexically depth/token bounded and must fit the
8 MiB pre-DOM parse limit.

## Edition preflight

Run the preflight after the exact JAR is successfully loaded in each fresh edition. It verifies unauthenticated `401`,
authenticated identity and protocol, ping, exact Community/Professional tool, prompt, fixed-resource, and resource-template
identifier sets, the bounded read-only correlation schema, project binding, one no-side-effect read-only tool call,
fixed-cardinality diagnostics redaction, and session
`DELETE`. The running extension schedules a hash of its own regular non-symlink code-source JAR as soon as the server
manager is constructed, off the UI thread, and the preflight requires that digest to equal the separately opened
candidate file; version equality alone is not accepted.

```bash
scripts/run-exact-burp-preflight.py \
  --approved-disposable-project \
  --edition community \
  --token-file <private-current-token-file> \
  --forbidden-value-file <private-marker-file> \
  --candidate-jar <exact-downloaded-candidate.jar> \
  --expected-jar-sha256 <sha256> \
  --expected-source-commit <full-commit> \
  --expected-server-version <candidate-version> \
  --burp-pid <pid> --max-rss-mib 6144 \
  --output <new-private-community-preflight.json>
```

Repeat with a separate fresh Community/Professional data directory and project, current token, PID, `--edition`, and
output. The report intentionally does not claim to observe the Burp application version, OS, Java runtime, successful UI
load action, or fresh-project creation; retain separate secret-free evidence for those facts.

## Fresh-project scale and lifecycle

Run `run-live-websocket-scale.py` only after confirming the fresh project has the required below-10,000 no-match
baseline. Its exact staged accounting must fail rather than reuse a project with pre-existing history. Run
`run-live-lifecycle-soak.py` after scale if the candidate gate requires it. The commands and interpretation limits are in
[PERFORMANCE.md](PERFORMANCE.md).

Professional and Community runs are separate lifecycles. Never reuse the bearer, project, data directory, or a successful
Community scale report as Professional evidence.

## Diagnostics-gated cancellation

With no other MCP client or event stream connected, `run-live-cancellation-barrier.py` first requires exactly its target
and observer sessions and completes one exact 10,000-record private no-match read. It then starts bounded search attempts
and uses the separate observer session to require both `activeHttpCalls >= 2` and `webSocketSearchActive >= 1`. The latter
is the target-side processing barrier; HTTP admission alone is not cancellation evidence. Only after both conditions are
observed does the runner close the target POST socket and send an authenticated `DELETE` for that target session. A pass
additionally requires an aborted rather than completed response, a one-count increase in the server-side WebSocket-search
cancellation outcome with no completed-search increase, return to an idle WebSocket-search and observer-only HTTP/session
plateau, no retained approval/event-stream state, and a successful fresh verifier session. The live artifact proves
cancellation after the ordered abort-and-delete sequence; it does not attribute that outcome to either action in isolation.

```bash
scripts/run-live-cancellation-barrier.py \
  --approved-disposable-project \
  --operator-confirmed-data-read-approved \
  --edition professional \
  --token-file <private-current-token-file> \
  --candidate-jar <exact-downloaded-candidate.jar> \
  --expected-jar-sha256 <sha256> \
  --expected-source-commit <full-commit> \
  --expected-server-version <candidate-version> \
  --burp-pid <pid> --max-rss-mib 6144 \
  --output <new-private-cancellation-report.json>
```

If every bounded attempt completes before the observer sees target-side WebSocket processing, the result is a failed
precondition, not cancellation evidence. If work completes after the barrier despite authenticated session deletion, the
run fails rather than retrying with a consumed session. This runner proves cancellation after caller disconnect plus
authenticated session termination for a read-only history call; it does not prove mutation cancellation, extension unload
during work, or project-transition handling.

## Scenario claims and finalization

Create one reviewed JSON document under the evidence root:

```json
{
  "schemaVersion": 1,
  "scenarios": {
    "catalogEditionGating": {
      "status": "PASS",
      "evidence": ["evidence/catalog-gating-record.json", "evidence/catalog-gating.json"],
      "notes": "Both exact edition preflights passed."
    }
  }
}
```

The real document must contain exactly all 13 scenario keys from the
[release smoke matrix](RELEASING.md#burp-smoke-matrix). Each claim contains exactly `status`, `evidence`, and `notes`.
Allowed statuses are `PASS`, `FAIL`, `BLOCKED`, and `NOT RUN`.

Each `PASS` or `FAIL` claim requires a unique scenario-record JSON followed by one or more objective evidence files. The
record is candidate- and scenario-bound and hashes every following file in the same order:

```json
{
  "schemaVersion": 1,
  "scenario": "catalogEditionGating",
  "status": "PASS",
  "sourceCommit": "<full-commit>",
  "candidateJarSha256": "<sha256>",
  "serverVersion": "<candidate-version>",
  "editions": ["community", "professional"],
  "checks": [
    {
      "name": "catalog-gating",
      "path": "evidence/catalog-gating.json",
      "sha256": "<evidence-sha256>",
      "result": "pass"
    }
  ]
}
```

Professional Scanner/Collaborator and scope/Scanner-uncertain records require Professional evidence; every other record
requires both editions. Scenario-record paths and every objective evidence path are unique across scenarios. A `PASS`
record may contain only passing checks, while a `FAIL` record must contain a failed check.
Evidence paths are canonical POSIX-relative spellings below the root, may not traverse or contain symlink components,
and must name bounded regular files. Distinct paths must also identify distinct physical files; hard-link aliases are
rejected. The finalizer requires POSIX directory-descriptor support, opens every component relative to stable directory
descriptors, captures each evidence file once under per-file/aggregate bounds, and uses those same bytes for schema
checks, privacy checks, and the checksum index. A Windows Burp run may be finalized from a clean Linux/macOS evidence
workspace after byte-preserving transfer. One
arbitrary, swapped, or shared file therefore cannot make all 13 scenarios eligible.

Finalize only after both edition preflights and all scenario reviews are present:

```bash
scripts/finalize-exact-burp-smoke.py \
  --root <smoke-evidence-root> \
  --community-preflight evidence/community-preflight.json \
  --professional-preflight evidence/professional-preflight.json \
  --scenario-claims SCENARIO_CLAIMS.json \
  --candidate-jar assets/independent-mcp-bridge-all.jar \
  --expected-jar-sha256 <sha256> \
  --expected-source-commit <full-commit> \
  --expected-server-version <candidate-version> \
  --forbidden-value-file <private-current-or-retired-token-file> \
  --output SCENARIO_MATRIX.json \
  --workflow-results-output PRIVATE_WORKFLOW_RESULTS.json \
  --require-all-pass
```

Repeat `--forbidden-value-file` for every current/retired edition token and private marker used during the workflow; at
least one private mode-0600 value file is mandatory.

The matrix is always honest: any `FAIL`, `BLOCKED`, or `NOT RUN` produces disposition `WITHHOLD` and
`protectedSmokeEligible: false`. The single-line protected-workflow results file is created only when both exact edition
preflights pass and all 13 scenarios are `PASS`; otherwise it remains absent. Supplying `--require-all-pass` returns a
non-zero status after writing the withholding matrix. The protected `release-smoke` workflow still independently verifies
the immutable draft and requires protected-environment approval; this local output is not a `smoke_run_id`.

## Cleanup

Each live helper sends authenticated session `DELETE` in its cleanup path and fails its report if a created session was
not deleted. After an edition workflow, stop the endpoint, unload the extension, exit the disposable Burp process, verify
listener ownership/closure, remove private bearer and marker files, remove the disposable data directory/project, restore
preferences and clipboard from private backup, and confirm the source checkout remains clean. Never delete or replace an
immutable draft/tag/asset while cleaning local evidence.

Run the standard-library contract tests with:

```bash
python3 scripts/test-live-mcp-harness.py
python3 scripts/test-exact-smoke-contract.py
```
