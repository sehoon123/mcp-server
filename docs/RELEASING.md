# Independent release process

This document defines the target release process for the independently maintained `sehoon123/mcp-server` fork. It is a
release gate, not a description of PortSwigger's process and not evidence that every control is already automated. The
version sequence and implementation milestones are tracked in
[NEXT_RELEASE_ROADMAP.md](NEXT_RELEASE_ROADMAP.md).

The checked-in `release-draft.yml` creates a one-shot draft only. The separately checked-in `release-smoke.yml` and
`release-publish.yml` workflows record exact-byte maintainer evidence and perform no-rebuild publication. A successful
local build or draft workflow is not a release.

## Release principles

1. **Independent identity:** artifacts must be clearly identified as an unofficial independent fork while preserving
   upstream authorship and copyright.
2. **Immutable source:** one protected, immutable full commit SHA is tested, built, tagged, attested, and published.
3. **Least privilege:** project code and downloaded build dependencies never execute with release-write or OIDC
   credentials.
4. **Reproducibility:** two isolated builds produce identical JAR and SBOM bytes.
5. **Complete distribution:** required licenses, notices, corresponding-source information, SBOM, checksums, and
   provenance ship with the binary.
6. **Human Burp verification:** automation is followed by a recorded smoke test using the exact candidate bytes.
7. **No replacement:** a published tag or executable asset is never moved, deleted, or overwritten to correct a defect.
   Corrections use a new patch version.

No upstream pull request is required to release this fork. The maintainer is responsible for security response, license
compliance, support claims, release integrity, and avoiding confusion with an official PortSwigger build.

## Fork identity gate

Complete this before publishing under the independent release process:

- choose a distinct extension/product name and BApp UUID;
- identify the fork maintainer/distributor in `BappManifest.bmf`;
- replace distributor metadata such as JAR `Implementation-Vendor` with the fork identity;
- add a prominent statement such as “Unofficial independent fork; not published or supported by PortSwigger” to the
  README, BApp description, extension UI/about text, and release notes;
- update installation/support/source links to `sehoon123` repositories;
- add a dated fork/modification notice that records the upstream repository and base commit;
- preserve original author and copyright notices;
- keep the existing Kotlin package namespace only where technical compatibility requires it; a package name must not be
  used as distributor branding.

Treat product name, UUID, vendor, source URL, support URL, and release account as one identity. A partial rename is not
sufficient.

## Repository controls

Configure these controls in GitHub before enabling publication:

- protected `main` with required read-only CI;
- protected `v*` tags restricted to authorized maintainers;
- Actions restricted to approved, full-SHA-pinned actions;
- minimal default `GITHUB_TOKEN` permissions;
- immutable releases enabled for the repository;
- a fine-grained repository secret named `IMMUTABLE_RELEASES_READ_TOKEN`, scoped to Administration (read-only), used
  only to fail closed on the repository immutability setting before publication;
- periodic maintainer review of GitHub Actions, Gradle, npm, wrapper, lock, and verification-metadata updates;
- GitHub Issues enabled with the exact labels `priority:P0`, `priority:P1`, `priority:P2`,
  `gate:release-blocker`, and `gate:non-blocking`; and
- private reporting instructions and an owner for release/security incidents.

GitHub Issues are the machine-readable defect authority for the RC observation gate. Every issue created from the RC's
public `published_at` timestamp through stable publication must have exactly one of the three priority labels and exactly
one of the two gate-disposition labels. Independently, every currently open `gate:release-blocker` issue, regardless of
creation date, is checked for P0/P1 priority. Missing labels, disabled Issues, duplicate dispositions, untriaged issues,
more than 1,000 bounded records in either query, or an open release-blocking P0/P1 fails closed. Titles and bodies are
never copied into release evidence. This deliberately gives public issue intake a fail-closed availability effect: an
untriaged report pauses publication, and exceeding either bounded query requires a successor RC rather than silently
truncating evidence. Current labels/state and repository-admin classification are trusted GitHub state; the attested
issue-number snapshot supports audit but cannot prevent a later administrator relabel, transfer, or deletion.

GitHub does not expose draft releases to an Actions integration token limited to `contents: read`. The exact-byte smoke
draft-validation job and the read-only publication preflight therefore request an ephemeral `contents: write` token solely
to read the draft metadata and assets. Those jobs do not check out or execute repository or release-asset code and issue
no release mutation. Record upload and attestation run in separate jobs without `contents: write`. The separate
`IMMUTABLE_RELEASES_READ_TOKEN` remains limited to the repository-immutability check.

The release workflows do not use GitHub environments or required-reviewer approvals. Remote repository settings cannot
be proved by source review, so record API output for each release audit.

## Version and source preparation

A release candidate starts from a reviewed, clean commit on protected `main`.

### 1. Select the version

For `X.Y.Z`, update and reconcile:

- `gradle.properties`: `version=X.Y.Z`
- `BappManifest.bmf`: `ScreenVersion: X.Y.Z`
- `BappManifest.bmf`: `SerialVersion` strictly greater than every SemVer-tagged ancestor using the same BApp UUID (the immutable draft identity job enforces this)
- release title/tag: `vX.Y.Z`
- release notes and compatibility statements
- `docs/VULNERABILITY_REPORT.md`: version, date, reviewed source-commit marker, dependencies, and results; the immutable
  draft replaces that single marker in the staged asset with the resolved commit (a source file cannot contain its own
  commit SHA without creating a self-reference)
- any document that calls a different version “current production”; during RC7-to-stable promotion, only the four
  explicitly allowed stable-promotion paths may change before publication, so update any other prose in a reviewed
  post-publication follow-up rather than widening the observed source delta

The JAR `Implementation-Version` is generated from the Gradle version. Verify it from the candidate bytes rather than
assuming the build file was used correctly.

### 2. Freeze source and dependencies

Before tagging:

- all release-blocking security/correctness findings are fixed with regression tests;
- `git status --porcelain --untracked-files=all` is empty;
- the embedded proxy provenance resolves to the reviewed companion commit and binary hash;
- Gradle wrapper distribution checksum, dependency verification metadata, and dependency locks are reviewed;
- conformance npm dependencies are installed from a checked-in lockfile with integrity metadata;
- the exact JDK/container image and build tools are pinned;
- the SBOM license map has no “unknown means Apache-2.0” fallback;
- the third-party license/NOTICE bundle is regenerated and reviewed;
- `security/release-maven-coordinates.txt` still exactly matches the reviewed canonical 204-coordinate set; and
- the point-in-time OSV and npm audit queries are rerun for the immutable candidate and pass the checked-in fail-closed
  policy.

### 3. Create an immutable tag

Preferred trigger: a signed annotated, protected tag that points to the reviewed full SHA.

```bash
set -euo pipefail
test -z "$(git status --porcelain --untracked-files=all)"
git rev-parse HEAD
git tag -s vX.Y.Z -m 'vX.Y.Z'
git show --no-patch --show-signature vX.Y.Z
git push origin vX.Y.Z
```

The draft workflow fails closed unless GitHub reports the annotated tag signature as valid and the tagger email matches
the reviewed maintainer identity. Once a tag is pushed, do not move it. A failed candidate is corrected under a new
version.

Before signing, add and review `docs/releases/<version>.md` as specified by `docs/releases/README.md`. Trigger the
workflow at the candidate tag itself (select the tag as the workflow ref, or dispatch the API call with `ref` set to the
tag), and provide the same tag and its 40-character peeled commit SHA as inputs. This equality is required because GitHub
OIDC provenance binds the source repository digest to the workflow's `GITHUB_SHA`. Never dispatch from `main` while
asking the workflow to build another commit. The read-only identity job resolves the SHA once and passes it to every
checkout; matrix and package jobs must not independently resolve a movable ref.

## Target workflow architecture

### Job A — identity (`contents: read`)

- resolve the protected tag and peeled commit;
- verify the tag signature/authorized actor;
- verify Gradle, BApp, tag, and requested version agree;
- emit one full source SHA;
- fail if the SHA is not reachable from protected `main`;
- make no release changes.

### Job B — tests and conformance (`contents: read`)

- checkout the emitted SHA with `persist-credentials: false`;
- use the pinned JDK/container and verified dependencies;
- run the full test suite and client matrix;
- run stable conformance and the checked-in modern expected-failure baseline;
- upload reports under a retention policy;
- execute with no OIDC, attestation, or release-write permission.

### Job C — exact vulnerability evidence (`contents: read`)

- checkout the emitted server SHA and the proxy SHA named by its embedded provenance;
- resolve both exact Gradle project-plugin graphs and add the reviewed settings-plugin implementations to both locked dependency graphs;
- require exact equality with canonical `security/release-maven-coordinates.txt` (204 coordinates, SHA-256 `2253cc639c78b44cd2c8356dd868e4e95287ca03af5a7cabce85495517a02d51`);
- submit that exact set to OSV and fail on a missing response, count mismatch, malformed response, or any vulnerability;
- run dev-inclusive lock-only npm audit without lifecycle scripts and reject high, critical, or unreviewed package nodes;
- accept only the checked-in moderate conformance dependency chain when it is present; and
- archive normalized evidence bound directly to the release tag, server SHA, proxy SHA, and coordinate identity for
  checksum and attestation.

Local queries are review input only. Publication evidence comes from the authoritative immutable tagged workflow and is
bound to the release tag, server SHA, proxy SHA, exact coordinate-set identity, workflow run, release checksums, and
provenance.

### Jobs C1/C2 — isolated builds (`contents: read`)

- checkout the same SHA independently with no persisted credentials;
- run clean, no-build-cache packaging and SBOM generation;
- publish candidate artifacts by digest;
- compare the two JARs and two SBOMs byte-for-byte in a validation job;
- record JDK, Gradle, OS/container digest, and resolved dependency metadata.

Two builds in one workspace detect accidental nondeterminism but do not detect a consistently compromised dependency or
mutable runner. Independent jobs and verified inputs are required for release-grade reproducibility. The isolated jobs
run inside the reviewed `eclipse-temurin` JDK 21 image pinned by OCI manifest-list digest in the workflow; changing that
digest is a release-input update requiring platform-specific digest and JDK-version review.

### Job D — artifact/legal validation (`contents: read`)

- inspect archive timestamps, duplicate names, embedded proxy, manifest, and prohibited package families;
- validate the SBOM against CycloneDX 1.6 JSON Schema;
- reconcile every shipped component with an explicit reviewed license entry;
- assert that required license and NOTICE files exist inside the JAR and release bundle;
- generate checksums from the final staged bytes;
- enforce an exact filename allowlist.

### Job E — attest and create draft

This job may request `id-token: write`, `attestations: write`, and narrowly scoped release permission. It must:

- download only the validated digest-bound artifacts from prior jobs;
- execute no Gradle build, tests, npm packages, or repository scripts;
- bind provenance to the resolved source SHA and workflow identity;
- attest every distributed artifact, including the checksum and legal/source bundles;
- create a draft release only;
- scope `GH_TOKEN` to the individual GitHub CLI step rather than the whole job.

### Job F — exact-byte Burp smoke test

Download the draft artifact into a clean environment and record:

- release/tag/commit and JAR SHA-256;
- Burp version, edition, OS, and Java runtime;
- native MCP client and stdio proxy client versions;
- extension diagnostics showing the expected implementation version;
- pass/fail evidence for the smoke matrix below.

Do not rebuild for this step. Test the exact bytes that will be published.

The evidence handoff must be authenticated and digest-bound. Use the exact-candidate helpers and cleanup contract in
[EXACT_BURP_SMOKE.md](EXACT_BURP_SMOKE.md) to validate each edition, retain `PASS`/`FAIL`/`BLOCKED`/`NOT RUN` distinctly,
and build the local matrix. The helper emits the workflow's single-line all-pass input only when both edition preflights
and all 11 required scenarios pass; it never creates that input for a withheld matrix. Project-transition and
uncertain-execution reconciliation scenarios are outside the release contract rather than recorded as passes. The
helpers are candidate source and cannot retroactively validate an earlier immutable tag.

Use the manually dispatched `release-smoke` workflow to download the draft JAR, compute its digest, and emit
`smoke-result.json` containing the tag, source SHA, JAR digest, tester GitHub identity, timestamp, environment versions,
and per-scenario results. Attest that record, upload it as an immutable workflow artifact, and record its run ID and
artifact digest. The publish job must independently download and verify the attestation, authorized tester identity,
all-pass result, tag/source identity, and matching JAR digest; an unchecked workflow input, local matrix, or editable
comment is not sufficient evidence.

The immutable candidate source and the release-control workflow revision are separate identities. If a workflow-only
defect is discovered after the candidate is tagged, a reviewed signed descendant on protected `main` may repair only
the orchestration without moving the tag, rebuilding, changing the draft, or replacing assets. The smoke attestation is
then bound to that workflow revision while its record remains bound to the tagged candidate source and exact JAR. Run
publication from the same `main` revision as the successful smoke run; any later `main` change requires a new smoke run.

### Job G — no-rebuild publication

After the smoke record succeeds, a minimal job must:

1. re-resolve and verify the protected tag and full SHA;
2. verify the draft still targets that SHA and is still a draft;
3. download every draft asset into a clean workspace;
4. enforce the exact asset allowlist and reject extras/missing files;
5. verify all checksums and GitHub/Sigstore attestations;
6. verify the recorded Burp smoke result references the same JAR digest;
7. publish without replacing any asset;
8. output the release URL, run URL, source SHA, and artifact digests.

The publish job performs no source build and runs no project-provided executable code.

### Job H — attested RC observation gate

Stable publication requires a successful `release-rc-observation.yml` run. The observation window starts at the
immutable public RC release's GitHub `published_at` timestamp and must be at least 604,800 seconds. Tag creation, draft
creation, or a local test does not start the clock. Dispatch the workflow from protected `main` with the published RC
tag/source SHA, its protected exact-byte smoke run ID, and its no-rebuild publication run ID.

The read-only observation job re-resolves the signed annotated tag, immutable prerelease, exact asset names/digests,
checksums, draft provenance, protected smoke attestation, publication-run timing, repository issue controls, complete
paginated issue triage, and the no-open-P0/P1 predicate. It emits a mode-0600 bounded JSON record containing public
identities, counts, issue numbers, and a canonical issue-snapshot digest, but no issue titles, bodies, credentials, raw
traffic, absolute local paths, or private identifiers. A separate no-checkout OIDC job attests that record. The RC smoke
artifacts must still be available both when observation runs and when stable publication independently re-verifies them;
the observation record and bundle must also still be available when stable publication runs. Each workflow retains its
artifacts for 90 days, making RC smoke expiry a hard stable-publication deadline.

Observation-to-stable continuity is deliberately narrower than ancestry and has two exact phases. The one-time RC7 gate
installation comparison must contain exactly these reviewed paths: `.github/workflows/build.yml`,
`.github/workflows/release-draft.yml`, `.github/workflows/release-publish.yml`,
`.github/workflows/release-rc-observation.yml`, `docs/NEXT_RELEASE_ROADMAP.md`, `docs/RELEASING.md`,
`scripts/rc_observation_contract.py`, `scripts/test-exact-smoke-contract.py`,
`scripts/test-rc-observation-contract.py`, and `scripts/test-release-vulnerability-gate.py`. The attested observation
record pins that workflow revision and exact path set. This one-time exception exists because the observation gate was
implemented after RC7; its code content is trusted through reviewed protected-`main` commit identity rather than a claim
that RC7 exercised the release builder or gate itself. Fresh stable reproducibility, vulnerability, provenance, and Burp
smoke gates remain mandatory. This is an intentional freeze, not a permissive allowlist: any additional `main` path
before observation makes RC7 ineligible and requires RC8.

From the observation revision to the stable source, the comparison must contain exactly `gradle.properties`,
`BappManifest.bmf`, `docs/VULNERABILITY_REPORT.md`, and `docs/releases/<stable-version>.md`. The first file may change
only its single `version=` line; the manifest may change only `ScreenVersion` and an increasing `SerialVersion`; the
vulnerability report may change only its heading, review date, and candidate-version lines; and the stable release
fragment must be non-empty. Gate,
build, smoke, runtime source, dependency, proxy-pin, or any other change after observation requires a successor RC and a
new window. Stable publication additionally requires its workflow revision to equal the stable tagged source commit; a
post-tag workflow-only repair therefore cannot publish that stable tag. The stable draft still reruns reproducibility,
vulnerability, provenance, and exact-byte Burp gates.

`release-publish.yml` requires `rc_observation_run_id`, `observed_rc_tag`, and `observed_rc_source_sha` for a stable tag
and refuses all three for a prerelease tag. Both its read-only preflight and no-rebuild publication job independently
verify the observation run and attestation, re-resolve the immutable RC/tag/asset snapshot, recompute continuity, and
re-query current issue triage before publication. The stable draft still needs its own reproducible build, vulnerability
evidence, exact-byte Community/Professional smoke run, and provenance; RC smoke evidence is never accepted as stable
exact-byte evidence. Publish nevertheless re-verifies the RC JAR's draft provenance, RC smoke run/attestation, and RC
publication run independently rather than trusting only the observation producer. If the companion proxy `main` moves
away from the immutable pin before stable draft creation, the stable flow fails closed and requires a successor RC.

## Required release assets

Use stable names and include every other distributed asset in `SHA256SUMS`. Exclude `SHA256SUMS` itself and explicitly
identified detached verification metadata whose format cannot be self-referential.

| Asset | Requirement |
| --- | --- |
| `independent-mcp-bridge-all.jar` | Reproducible extension containing the verified proxy and required legal entries |
| `bom.cdx.json` | CycloneDX 1.6 with exact versions, hashes, explicit licenses, and dependency relationships |
| `SHA256SUMS` | Hash of every other distributed asset except explicitly identified detached verification metadata |
| `LICENSE` | Complete project GPL license |
| `NOTICE.md` | Distributor, upstream copyright, trademark, and no-endorsement notice |
| `THIRD_PARTY_NOTICES.md` | Component/source/license index; not a replacement for license texts |
| `Apache-2.0.txt`, `MIT-SLF4J.txt` | Reviewed third-party license texts and attribution |
| `runtime-licenses.properties` | Exact reviewed runtime `group:name` to SPDX mapping used to generate the SBOM |
| `FORK_NOTICE.md` | Independent-fork identity, upstream base, modification/distributor notice |
| `CORRESPONDING_SOURCE.md` | Durable exact source instructions for server and embedded proxy |
| `independent-mcp-bridge-X.Y.Z-source.tar.gz` | Exact tagged extension source archive |
| `MIGRATION_V4_8.md` | New UUID/name/client-key migration and side-by-side warning |
| `VULNERABILITY_REPORT.md` | Release-specific reviewed policy, scope, accepted exception, version, and commit |
| `OSV-COORDINATES.txt`, `OSV-RESPONSE.json` | Canonical exact Maven query set and fresh zero-finding OSV response |
| `NPM-AUDIT.json` | Normalized npm result under the reviewed conformance-development exception policy |
| `VULNERABILITY_EVIDENCE.json` | Release-tag/source/proxy binding, query identities, result counts, and authoritative vulnerability-gate outcome |
| `SOURCE_IDENTITY.json`, `RELEASE_NOTES.md` | Tag, full SHA, artifact and vulnerability-evidence digests, migration, and reviewed change range |
| `provenance.intoto.jsonl` | Verifiable binding between staged artifacts, workflow, repository, and source SHA |

GitHub's automatically generated server source archive does not by itself contain the companion proxy's corresponding
source. Include a source bundle or durable exact instructions that cover both repositories and the embedded binary.

The shaded JAR must not blanket-delete license and NOTICE material without replacing it with a complete, reviewed,
collision-safe bundle. CI should fail on unknown components or missing legal entries.

## Release build commands

After the reviewed candidate commit is on protected `main`, run the canonical local build preflight:

```bash
./gradlew clean test embedProxyJar generateSbom --no-build-cache
```

A local reproducibility check keeps the first outputs outside `build/`:

```bash
tmp=$(mktemp -d)
./gradlew clean embedProxyJar generateSbom --no-build-cache
cp build/libs/independent-mcp-bridge-all.jar "$tmp/first.jar"
cp build/reports/compliance/bom.cdx.json "$tmp/first-bom.json"
./gradlew clean embedProxyJar generateSbom --no-build-cache
cmp "$tmp/first.jar" build/libs/independent-mcp-bridge-all.jar
cmp "$tmp/first-bom.json" build/reports/compliance/bom.cdx.json
```

Inspect identity and archive policy:

```bash
unzip -p build/libs/independent-mcp-bridge-all.jar META-INF/MANIFEST.MF
jar tf build/libs/independent-mcp-bridge-all.jar | sort
sha256sum build/libs/independent-mcp-bridge-all.jar build/reports/compliance/bom.cdx.json
```

Local matching builds are useful preflight evidence only. The protected workflow remains authoritative.

## Burp smoke matrix

At minimum, exercise the 11 required scenarios:

1. clean extension load, unload, and proxy checksum/provenance diagnostics;
2. start, stop, restart, occupied-port failure, correction, extension reload, and exact private equality of the local
   bearer credential across a project switch and full Burp process restart, followed by explicit-rotation cutover and
   another restart;
3. native Streamable HTTP initialize, initialized notification, ping, list, call, and authenticated DELETE;
4. stdio proxy initialize, one read call, one action denial, and graceful EOF cleanup;
5. exact Community tool/resource/prompt catalog and Professional-only gating;
6. Professional Scanner and Collaborator paths for every release that claims Professional support;
7. Repeater/Intruder/Organizer routing without hidden network transmission;
8. stable-ID outbound replay with independent exact-request and outbound-target authorization;
9. large history/issue reads confirming bounds and cancellation without UI stalls;
10. audit, diagnostics, and error paths confirming no credentials, bodies, paths, or header values leak; and
11. extension unload while a cancellable background operation is active.

A smoke test is invalid if the JAR digest differs from the draft asset. A timeout, missing report, failed fresh-project
baseline, completed-before-barrier call, `BLOCKED`, or `NOT RUN` result is not a pass. Do not dispatch the
`release-smoke` workflow until the local exact matrix is eligible.

## Release notes

Release notes must include:

- independent-fork disclaimer and support/source URL;
- exact full commit SHA;
- previous release tag and a non-empty, reviewed change range;
- protocol/SDK/Burp compatibility;
- security-relevant behavior and approval changes;
- migrations or wire-compatibility changes;
- verification summary and successful workflow URL;
- JAR, SBOM, and vulnerability-evidence SHA-256;
- instructions for checksum and attestation verification;
- known limitations that remain acceptable for this release.

The draft workflow selects the nearest strict-SemVer tag on first-parent history that has a published, non-draft GitHub
release, records it in the notes, validates ancestry, and rejects an empty change range. The reviewed compatibility, security/approval,
and known-limitations sections come from the exact tagged `docs/releases/<version>.md` fragment; generated source,
workflow, change-range, verification, and digest data cannot be replaced by free-form dispatch input.

## Consumer verification

Document both integrity and publisher/source verification. A checksum downloaded beside the JAR detects corruption but
not compromise of the release account.

Example for verifying a published release produced by the checked-in attestation workflow:

```bash
sha256sum -c SHA256SUMS
gh attestation verify independent-mcp-bridge-all.jar --repo sehoon123/mcp-server
gh attestation verify bom.cdx.json --repo sehoon123/mcp-server
```

Also document how to verify the protected tag signature and compare the attested source SHA with the release notes.

## Failure and correction policy

### Before publication

- leave the draft unpublished;
- preserve logs and failed artifacts for diagnosis under the retention policy;
- do not weaken or skip the failing gate;
- fix on a new commit and version/tag when an immutable tag was already pushed.

### After publication

- never use `gh release upload --clobber` against a published release;
- never move the published tag;
- mark the affected release as withdrawn or superseded with a prominent explanation;
- publish corrected bytes under a new patch version;
- retain the old checksum/provenance evidence so previous downloads remain identifiable;
- notify users when the defect affects security, compatibility, or binary identity.

## Current workflow status

`release-draft.yml` requires one full 40-character source SHA, checks out that SHA without persisted credentials in every
source job, binds OSV/npm vulnerability evidence directly to the release tag, runs the client/conformance matrices,
compares JAR and SBOM bytes from two isolated builders, stages an exact legal/source asset allowlist, and passes only
downloaded bytes to the OIDC/repository-write draft job. The draft job runs no project code, revalidates checksums and
source identity, creates an attestation bundle, fails if the release already exists, and never uses `--clobber`.

`release-smoke.yml` records a maintainer tester attestation for the exact draft JAR. It does not pretend to run Burp on a
GitHub-hosted runner: the tester must first perform the documented Community and Professional matrix and supply the exact
downloaded JAR digest and environment versions. The workflow independently downloads the draft, verifies that digest
and source identity, emits a bounded `smoke-result.json`, and attests the record in a separate no-checkout OIDC job.

`release-publish.yml` supports both SemVer prereleases and stable tags. Its read-only preflight and publication job
independently re-resolve the signed tag, protected-main ancestry, one-shot draft, exact asset/API-digest snapshot,
checksums, source identity, release body, draft provenance, authorized smoke workflow run, tester identity, smoke
attestation, and JAR digest. Stable tags additionally require the attested seven-day RC observation run and live
release-blocking issue revalidation described in Job H; prerelease tags reject observation inputs. The publication step
first checks the repository immutable-release setting using a read-only administration token, sends only `draft=false`,
requires the resulting release to report `immutable=true`, does not rebuild or replace assets, and is followed by an
anonymous checksum/source/provenance check.

Any publication remains blocked until:

- GitHub immutable releases are enabled and write access to drafts/tags is restricted;
- the checked-in Gradle/npm locks and verification metadata are reviewed for the candidate;
- the exact-byte Community and Professional matrix is actually performed and its smoke workflow succeeds;
- a stable tag has a successful seven-day RC observation attestation with unexpired artifacts, allowed-path continuity,
  and no current untriaged or open release-blocking P0/P1 issue; and
- the unauthenticated post-publication job succeeds and its run is retained.

Do not use the manually built and later corrected v4.7.0 publication as evidence that the target process ran.

## Final release checklist

- [ ] Fork name, UUID, vendor, maintainer, links, and disclaimer are consistent.
- [ ] Protected main/tag controls and immutable-release settings are recorded.
- [ ] Version, BApp metadata, tag, manifest, reports, and notes agree.
- [ ] Source and proxy checkouts are clean and pinned to reviewed full SHAs.
- [ ] Full tests, client matrix, conformance, and required manual Burp matrix pass.
- [ ] Stable publication inputs reference a successful attested RC observation whose window is at least 604,800 seconds
  after the RC's public `published_at` timestamp.
- [ ] Two isolated builds produce identical JAR and SBOM bytes.
- [ ] Wrapper, Gradle/npm dependencies, JDK/container, and Actions are integrity-pinned.
- [ ] SBOM schema, hashes, relationships, and explicit licenses validate.
- [ ] JAR and release bundle contain complete GPL/Apache/MIT/NOTICE/fork/source material.
- [ ] Exact asset allowlist and `SHA256SUMS` validate.
- [ ] Attestations bind every artifact to the intended source SHA.
- [ ] Draft asset digest equals the manually smoke-tested digest.
- [ ] Publish job revalidated tag, assets, checksums, and attestations.
- [ ] Public latest links, downloads, checksums, and attestations were rechecked from a clean environment.
- [ ] Release and run URLs, full SHA, and artifact hashes were archived.
