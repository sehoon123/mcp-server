# Independent release process

This document defines the target release process for the independently maintained `sehoon123/mcp-server` fork. It is a
release gate, not a description of PortSwigger's process and not evidence that every control is already automated. The
version sequence and implementation milestones are tracked in
[NEXT_RELEASE_ROADMAP.md](NEXT_RELEASE_ROADMAP.md).

The checked-in `release-draft.yml` currently builds or updates a **draft only**. Publication needs a separate protected
job that revalidates the immutable source, artifacts, and attestation. A successful local build is not a release.

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

- protected `main` with required read-only CI and review;
- CODEOWNERS/review requirements for workflows, Gradle files, proxy provenance, manifests, and legal files;
- protected `v*` tags restricted to authorized maintainers;
- Actions restricted to approved, full-SHA-pinned actions;
- a protected `release` environment requiring human approval;
- minimal default `GITHUB_TOKEN` permissions;
- immutable releases, if available for the repository;
- Dependabot or Renovate coverage for GitHub Actions and Gradle dependencies;
- private reporting instructions and an owner for release/security incidents.

Remote repository settings cannot be proved by source review. Record screenshots or API output for each release audit.

## Version and source preparation

A release candidate starts from a reviewed, clean commit on protected `main`.

### 1. Select the version

For `X.Y.Z`, update and reconcile:

- `gradle.properties`: `version=X.Y.Z`
- `BappManifest.bmf`: `ScreenVersion: X.Y.Z`
- `BappManifest.bmf`: monotonically increasing `SerialVersion`
- release title/tag: `vX.Y.Z`
- release notes and compatibility statements
- `docs/VULNERABILITY_REPORT.md`: version, date, commit, dependencies, and results
- any document that calls a different version “current production”

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
- the point-in-time vulnerability query is rerun for runtime and build-plugin graphs.

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

If signed tags are not yet available, use an annotated protected tag and document the temporary limitation. Once a tag
is pushed, do not move it. A failed candidate is corrected under a new version.

A workflow-dispatch input must be a 40-character full SHA, never `main` or another movable branch. Resolve it once in a
read-only identity job and pass that output to every checkout. Matrix and package jobs must not independently resolve a
movable ref.

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

### Jobs C1/C2 — isolated builds (`contents: read`)

- checkout the same SHA independently with no persisted credentials;
- run clean, no-build-cache packaging and SBOM generation;
- publish candidate artifacts by digest;
- compare the two JARs and two SBOMs byte-for-byte in a validation job;
- record JDK, Gradle, OS/container digest, and resolved dependency metadata.

Two builds in one workspace detect accidental nondeterminism but do not detect a consistently compromised dependency or
mutable runner. Independent jobs and verified inputs are required for release-grade reproducibility.

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

The evidence handoff must be authenticated and digest-bound. Use a protected `release-smoke` environment workflow that
downloads the draft JAR itself, computes its digest, and emits `smoke-result.json` containing the tag, source SHA, JAR
digest, tester GitHub identity, timestamp, environment versions, and per-scenario results. Attest that record, upload it
as an immutable workflow artifact, and record its run ID and artifact digest. The publish job must independently download
and verify the attestation, authorized tester identity, all-pass result, tag/source identity, and matching JAR digest;
an unchecked workflow input or editable comment is not sufficient evidence.

### Job G — protected publication

After protected-environment approval, a minimal job must:

1. re-resolve and verify the protected tag and full SHA;
2. verify the draft still targets that SHA and is still a draft;
3. download every draft asset into a clean workspace;
4. enforce the exact asset allowlist and reject extras/missing files;
5. verify all checksums and GitHub/Sigstore attestations;
6. verify the recorded Burp smoke result references the same JAR digest;
7. publish without replacing any asset;
8. output the release URL, run URL, source SHA, and artifact digests.

The publish job performs no source build and runs no project-provided executable code.

## Required release assets

Use stable names and include every other distributed asset in `SHA256SUMS`. Exclude `SHA256SUMS` itself and explicitly
identified detached verification metadata whose format cannot be self-referential.

| Asset | Requirement |
| --- | --- |
| `burp-mcp-all.jar` | Reproducible extension containing the verified proxy and required legal entries |
| `bom.cdx.json` | CycloneDX 1.6 with exact versions, hashes, explicit licenses, and dependency relationships |
| `SHA256SUMS` | Hash of every other distributed asset except explicitly identified detached verification metadata |
| `LICENSE` | Complete project GPL license |
| `THIRD_PARTY_NOTICES.md` | Component/source/license index; not a replacement for license texts |
| third-party license/NOTICE bundle | Full applicable Apache/MIT texts and required upstream NOTICE content |
| `FORK_NOTICE.md` | Independent-fork identity, upstream base, modification/distributor notice |
| `VULNERABILITY_REPORT.md` | Release-specific point-in-time review naming version and commit |
| corresponding-source bundle or instructions | Durable exact source for server and embedded proxy, including build scripts |
| provenance/attestation | Verifiable binding between artifacts, workflow, repository, and source SHA |

GitHub's automatically generated server source archive does not by itself contain the companion proxy's corresponding
source. Include a source bundle or durable exact instructions that cover both repositories and the embedded binary.

The shaded JAR must not blanket-delete license and NOTICE material without replacing it with a complete, reviewed,
collision-safe bundle. CI should fail on unknown components or missing legal entries.

## Release build commands

The canonical local preflight is:

```bash
./gradlew clean test embedProxyJar generateSbom --no-build-cache
```

A local reproducibility check keeps the first outputs outside `build/`:

```bash
tmp=$(mktemp -d)
./gradlew clean embedProxyJar generateSbom --no-build-cache
cp build/libs/burp-mcp-all.jar "$tmp/first.jar"
cp build/reports/compliance/bom.cdx.json "$tmp/first-bom.json"
./gradlew clean embedProxyJar generateSbom --no-build-cache
cmp "$tmp/first.jar" build/libs/burp-mcp-all.jar
cmp "$tmp/first-bom.json" build/reports/compliance/bom.cdx.json
```

Inspect identity and archive policy:

```bash
unzip -p build/libs/burp-mcp-all.jar META-INF/MANIFEST.MF
jar tf build/libs/burp-mcp-all.jar | sort
sha256sum build/libs/burp-mcp-all.jar build/reports/compliance/bom.cdx.json
```

Local matching builds are useful preflight evidence only. The protected workflow remains authoritative.

## Burp smoke matrix

At minimum, exercise:

1. clean extension load and proxy checksum/provenance diagnostics;
2. start, stop, restart, occupied-port failure, correction, and extension reload;
3. native Streamable HTTP initialize, initialized notification, ping, list, call, and authenticated DELETE;
4. stdio proxy initialize, one read call, one action denial, and graceful EOF cleanup;
5. Community tool/resource/prompt catalog and Professional-only gating;
6. Professional Scanner and Collaborator paths for every release that claims Professional support; if that environment
   is unavailable, delay the release or explicitly remove the unverified support claim;
7. data access denied, allow once, allow for session, reset, and project transition;
8. Repeater/Intruder/Organizer routing without hidden network transmission;
9. stable-ID outbound replay with independent exact-request and outbound-target authorization;
10. scope and Scanner side effects, including denial and uncertain-execution presentation;
11. large history/issue reads confirming bounds and cancellation without UI stalls;
12. audit, diagnostics, and error paths confirming no credentials, bodies, paths, or header values leak;
13. extension unload while no job is active and while a cancellable background operation is active.

A smoke test is invalid if the JAR digest differs from the draft asset.

## Release notes

Release notes must include:

- independent-fork disclaimer and support/source URL;
- exact full commit SHA;
- previous release tag and a non-empty, reviewed change range;
- protocol/SDK/Burp compatibility;
- security-relevant behavior and approval changes;
- migrations or wire-compatibility changes;
- verification summary and successful workflow URL;
- JAR and SBOM SHA-256;
- instructions for checksum and attestation verification;
- known limitations that remain acceptable for this release.

When generating changes from a checkout that already has the current tag, exclude it explicitly:

```bash
git describe --tags --abbrev=0 --exclude='vX.Y.Z' HEAD
```

Validate that the selected previous tag is an ancestor of the candidate.

## Consumer verification

Document both integrity and publisher/source verification. A checksum downloaded beside the JAR detects corruption but
not compromise of the release account.

Example after the target attestation workflow is implemented:

```bash
sha256sum -c SHA256SUMS
gh attestation verify burp-mcp-all.jar --repo sehoon123/mcp-server
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

## Current workflow migration

Until the checked-in workflows are split into the target jobs above:

- pass only an immutable full SHA as `target_ref`;
- manually confirm every matrix/package checkout resolved to that SHA;
- do not treat a same-job double build as independent reproducibility;
- do not publish a draft unless all required legal/source assets have been added and checksummed;
- recognize that the package job currently combines build execution with repository-write/OIDC permissions;
- recognize that `release-draft.yml` does not publish and there is no automated publication-time revalidation;
- do not use the manually built and later corrected v4.7.0 publication as evidence that the target release process ran.

The migration is complete only when build/test jobs are credential-free, the source identity is immutable across every
job, legal/source bundles are enforced, and a protected minimal publish job verifies the exact draft bytes.

## Final release checklist

- [ ] Fork name, UUID, vendor, maintainer, links, and disclaimer are consistent.
- [ ] Protected main/tag/environment controls are recorded.
- [ ] Version, BApp metadata, tag, manifest, reports, and notes agree.
- [ ] Source and proxy checkouts are clean and pinned to reviewed full SHAs.
- [ ] Full tests, client matrix, conformance, and required manual Burp matrix pass.
- [ ] Two isolated builds produce identical JAR and SBOM bytes.
- [ ] Wrapper, Gradle/npm dependencies, JDK/container, and Actions are integrity-pinned.
- [ ] SBOM schema, hashes, relationships, and explicit licenses validate.
- [ ] JAR and release bundle contain complete GPL/Apache/MIT/NOTICE/fork/source material.
- [ ] Exact asset allowlist and `SHA256SUMS` validate.
- [ ] Attestations bind every artifact to the intended source SHA.
- [ ] Draft asset digest equals the manually smoke-tested digest.
- [ ] Protected publish job revalidated tag, assets, checksums, and attestations.
- [ ] Public latest links, downloads, checksums, and attestations were rechecked from a clean environment.
- [ ] Release and run URLs, full SHA, and artifact hashes were archived.
