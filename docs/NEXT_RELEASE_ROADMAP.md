# Active release roadmap

**Status date:** 2026-09-21<br>
**Current candidate build:** `4.12.0-rc.5` / BApp SerialVersion 18 (canonical resource parts and cooperative read cancellation; publication gates remain open)<br>
**Last stable baseline:** `v4.7.0` / `a1579834995d90be62c269b0b602e6c789bf3a14`<br>
**Historical release candidate:** immutable `v4.11.0-rc.7` / `3eb0ff3bab614c1fe173b1c95c11dd5c3ee48121`; separate promotion track retired<br>
**Next stable target:** main-based successor, blocked pending reviewed identity/pin migration and fresh release evidence<br>
**Planning model:** gate-based; versions have no promised calendar date

This is the canonical near-term release plan for the independently maintained `sehoon123/mcp-server` fork. The longer
[ROADMAP.md](ROADMAP.md) remains the capability history and long-range backlog. If the two documents conflict, this
active roadmap controls release priority.

## Main-only policy update

The maintainer has retired the separate v4.11 promotion branch in favor of [main-only development](BRANCH_POLICY.md).
Its anchor remains in main history; historical tags, assets, and evidence remain immutable. The current workflow
refusals remain effective and no old observation/smoke record is transferred to a successor release. A future
main-based candidate needs reviewed successor identity/pins and fresh evidence before tagging/publication.

The historical sequence and v4.11 promotion milestones below are retained for provenance and planning context, **not
active instructions to recreate or publish the retired release line**. This update takes precedence over statements
below that call v4.11.0 the next stable target. Main integration with `NOT RUN` native checks is development progress,
not completion of any release gate.

## Historical product decision

The v4.8–v4.11 RC sequence accumulated the independent trust baseline, analysis workflows, correlation, lifecycle,
credential-persistence, and release-evidence work without publishing an intervening stable artifact. The next stable
release is therefore **v4.11.0**. Historical RC tags/releases remain immutable; `v4.11.0-rc.6` remains permanently
withheld, and the published `v4.11.0-rc.7` is the observed candidate. Its observation and four-path stable promotion
run only on protected `release/v4.11`, anchored at the reviewed release-control revision. After that anchor is created,
`main` may advance with later development, but those commits must never be merged or cherry-picked into the v4.11
release line. The RC7/v4.11.0 workflow pins are intentionally single-use: RC8, a v4.11 patch, or a later stable line
requires a reviewed re-parameterization rather than an operator-selected trust ref. The draft identity gate now
refuses unpinned successor v4.11 identities and every later main-line release until published `v4.11.0` can be pinned as
a non-ancestor SerialVersion and provenance predecessor; that refusal is not an operator-selectable escape hatch.

The required work was larger than a patch:

- network and request-routing approval semantics change;
- bounded Scanner behavior and stable identifiers may change;
- JSON Schema and MCP error contracts are tightened;
- the extension gets an independent fork identity, UUID, vendor, and support links;
- legal/source artifacts and the release pipeline change;
- existing installations may need explicit migration.

`v4.7.0` should be marked superseded after v4.11.0 is available. Its tag and published assets must not be moved or
replaced. Public validation began at `v4.8.0-rc.1` and now continues on immutable `v4.11.0-rc.7`; do not publish another
locally assembled corrective artifact or reuse RC evidence as stable exact-byte evidence.

## Release sequence

| Version | Theme | New public capability | Stable gate |
| --- | --- | --- | --- |
| `v4.8.0` | Independent Trust Baseline | None | Security, boundedness, identity, legal, and protected-release gates |
| `v4.9.0` | Analysis and Reusable Workflows | Session analyzer; project presets; planning-only Repeater prompt | Exact catalogs, project persistence, no-mutation client matrix |
| `v4.10.0` | Scale and Demand-driven Client UX | No default catalog expansion | Live scale evidence; separately reviewed UX scope |
| `v4.11.0` | Correlation, lifecycle, and release hardening | Bounded correlation and stable credential lifecycle | Immutable RC7, seven-day attested observation, fresh stable evidence |
| `v4.12.0` | Native utilities, evidence reporting, and local client UX | Five-client Setup Center; bounded native utilities; opt-in execution; human-reviewed issue reporting | Exact 24/38 catalogs, privacy/lifecycle/accessibility and real-client evidence |
| `v5.0.0` | Modern per-request MCP | Stable protocol/SDK/client capabilities only | All v5 gates plus a 14-day RC |

## v4.8.0 — Independent Trust Baseline

### Objective

Establish one independently branded, reproducible, legally complete release whose authorization, project boundary,
memory bounds, client contract, and exact published bytes are all testable.

### Epic A — authorization and project boundaries

Required work:

- make request-routing and outbound-network authority independent;
- require outbound-target approval immediately before every network transmission;
- keep exact derived-request review as an additional gate when enabled;
- ensure a session grant for Repeater, Intruder, Organizer, Comparer, or Decoder never grants network transmission;
- capture and recheck the Burp project across approvals, source snapshots, materialization, and side effects;
- add final project checks to Scanner/search/comparison/scope success paths;
- decide and document persistent hostname approval behavior when DNS answers or network class change.

Acceptance criteria:

- a routing-only session grant cannot authorize an HTTP replay;
- an outbound grant cannot authorize a non-network routing action;
- every routing/outbound grant combination has a deny and success regression test;
- deterministic A→B project-switch tests return `PROJECT_MISMATCH` without mixed-project output;
- no operation reports `not_started` after a Burp side effect may have executed;
- the DNS decision has either a controllable-resolver test or a documented, time-bounded accepted risk.

### Epic B — bounded Scanner and history processing

Required work:

- remove complete issue/object/JSON materialization before the legacy output limit;
- apply cumulative field, evidence-count, record-count, and byte budgets before conversion;
- slice Montoya byte arrays before text/base64 encoding;
- stop invoking additional getters after the output budget is exhausted;
- remove full issue-detail conversion from stable-ID generation;
- return complete structured JSON rather than a truncated JSON prefix;
- review WebSocket and context-menu snapshot copies/interruption while touching bounded history code.

Acceptance criteria:

- multi-megabyte detail, remediation, and evidence tests remain within the defined extension budget;
- metadata-only reads do not invoke detail or evidence getters;
- over-budget tests prove that unselected getters are not called;
- concurrent calls cannot multiply one unbounded issue into unbounded transient allocations;
- cursor/stable-ID migration behavior is explicit and tested;
- final output is complete, bounded, and includes visible truncation/continuation metadata.

### Epic C — schema and MCP result contract

Required work:

- make `JsonSchemaExactlyOneOf` enforce one non-null selected property;
- align nullable enum schemas with Kotlin explicit-null decoding;
- validate cross-field truth tables with a real JSON Schema validator;
- define one catalog-wide target policy for `structuredContent`, `isError`, status, execution state, and retry guidance;
- convert ordinary HTTP-search/Montoya failures to bounded structured outcomes;
- share canonical reference parsing between prompts, resources, and tools;
- reject invalid HTTP/2 pseudo-header namespaces, ordering/classes, names, and control characters before Montoya factories;
- test complete post-initialize lifecycles for every advertised protocol revision.

Acceptance criteria:

- absent/value/null truth tables agree between schema validation and endpoint decoding;
- every result family has success and failure contract tests for `isError` and retry behavior;
- malformed prompt references are rejected before a resource/tool is suggested;
- invalid HTTP/2 input reaches no factory or network call;
- older negotiated versions pass initialize, initialized, ping, discovery, one successful/failed call, resource/prompt,
  and DELETE tests.

### Epic D — safe errors, Swing, and owned background work

Required work:

- redact complete Authorization/Cookie/Set-Cookie and credential-bearing query values or emit fixed external errors;
- run file choosers and all Swing state access on the EDT;
- give provider installation one bounded, owned job and disable duplicate clicks;
- cancel or ignore provider completion after panel/extension cleanup;
- pass providers an immutable, validated snapshot of the displayed endpoint and token;
- keep persisted `enabled` state consistent with a failed server start;
- add interruption checks to long context-menu fallback scans.

Acceptance criteria:

- Basic, Digest, arbitrary Authorization schemes, cookies, quoted values, and query credentials survive no client/log
  error test;
- EDT seam tests cover chooser creation, display, and selected-file access;
- repeated install clicks serialize to one operation;
- unload-during-install produces no late modal or stale write;
- edit-endpoint-then-install uses exactly the displayed validated endpoint;
- a failed start does not silently retry on reload while the UI appears disabled.

### Epic E — independent fork identity and legal distribution

Implementation status (development branch):

- selected **Independent MCP Bridge**, UUID `c0a454c4079c4cecb627d928a92f9555`, vendor `sehoon123`, and the
  fork repository's source/support URLs;
- updated BApp/JAR/runtime/UI/client identity and added `FORK_NOTICE.md`, `NOTICE.md`, corresponding-source guidance,
  reviewed GPL/Apache/MIT material, and a v4.8 side-by-side migration guide;
- packaging now installs collision-safe `META-INF/legal/` entries, verifies reviewed legal-text hashes, requires an
  exact `group:name` license map, and rejects missing, stale, or malformed extension/proxy component records;
- the embedded proxy has an independent nested manifest/legal/runtime report, and packaging rejects the legacy vendor
  identity or any mismatch between the embedded report and source metadata;
- exact candidate release staging includes the legal, source, migration, identity, checksum, and provenance assets.

Remaining gate: publish the reviewed companion-proxy commit, rerun the source-guarded updater against that public commit,
then complete independent legal/source review and exact-candidate Community/Professional UI confirmation before an RC.

Required work:

- choose and document the independent product name, BApp UUID, maintainer, vendor, source URL, and support URL;
- add an unofficial-independent-fork statement to every user-facing distribution surface;
- preserve upstream authorship and copyright while adding the fork maintainer/distributor;
- provide a dated `FORK_NOTICE.md` with the upstream base and modification notice;
- replace blanket license/NOTICE removal with a collision-safe reviewed bundle;
- make SBOM licenses explicit and fail on unknown components;
- include durable corresponding-source instructions or bundles for the server and embedded proxy;
- update manual installation and client links to this fork.

Acceptance criteria:

- JAR, BApp metadata, Burp UI, README, release notes, and support links identify the same fork;
- no distributor/vendor/UUID/link implies that the artifact is an official PortSwigger release;
- required GPL, Apache-2.0, MIT, NOTICE, fork, and source material exists in both JAR and release staging;
- adding an unknown dependency or license fails packaging;
- a migration note explains the new UUID/name and how to disable the old extension.

The existing Kotlin package namespace may remain for technical compatibility; it is not distributor branding.

### Epic F — immutable, least-privilege release pipeline

Implementation status (development branch):

- `release-draft.yml` now accepts only a full source SHA, requires the workflow itself to run at the same existing
  signed annotated tag, checks authorized tagger/main ancestry, uses credential-free source jobs, runs pinned-lockfile
  conformance clients, compares two isolated builders, stages an exact allowlist, and gives write/OIDC permissions only
  to a no-checkout job that revalidates downloaded bytes and creates a one-shot non-clobbering draft;
- previous-tag selection walks exact SemVer tags on first-parent history, release-note fragments are source-reviewed,
  the change range cannot be empty, same-UUID BApp serials must increase, and every staged asset is bound to
  source/JAR/SBOM/vulnerability-evidence identity;
- pinned CycloneDX 1.6 schemas plus a locked Ajv validator check the SBOM before the exact hash/dependency/license policy;
- `build.yml` uses the same npm lockfile and uploads a staged, exact identity/legal asset set;
- the Gradle wrapper distribution checksum, dependency locks, and artifact/plugin verification metadata are checked in
  and must be reviewed with any dependency update;
- the immutable draft resolves both project-plugin graphs, requires exact equality with the reviewed 204-coordinate
  Maven set, reruns OSV and npm checks, and stages normalized evidence under checksums and attestation.

Remaining gate: protected tag configuration, a successful immutable candidate run producing fresh vulnerability
evidence, attested exact-byte Burp smoke evidence, the minimal no-rebuild publication workflow, and clean
post-publication verification.

Required work:

- resolve one immutable full source SHA and use it in every job;
- run all source builds/tests with read-only permissions and `persist-credentials: false`;
- split build, validation, attestation/draft, attested smoke evidence, and publication;
- compare JAR and SBOM bytes from two isolated builders;
- bind every attestation and smoke record to the source/tag/artifact digest;
- make the publish job download and revalidate an exact asset allowlist without running project code;
- reject dirty or unexpected companion-proxy source before copying a binary;
- add wrapper checksum, Gradle dependency/plugin verification and locking, and npm lockfile integrity;
- fix previous-tag selection for release notes;
- prohibit `--clobber` or any published-asset replacement path.

Acceptance criteria:

- no Gradle/npm/project script executes with release-write or OIDC permission;
- client matrix, builds, SBOM, notes, attestations, and release all identify one full SHA;
- two isolated builds produce byte-identical JAR and SBOM outputs;
- the attested smoke record includes tag, source SHA, JAR digest, tester identity, environment, and all scenario results;
- the publish job verifies the tag, checksums, attestations, smoke record, and exact files immediately before publication;
- protected branch/tag and immutable-release settings are captured in the release audit record;
- public artifacts are reverified from a clean unauthenticated environment after publication.

See [RELEASING.md](RELEASING.md) for the target job design and asset list.

### User-visible migration

Release notes for v4.8.0 must call out:

- the independent name/vendor/UUID and possible side-by-side old extension;
- required client configuration regeneration or server-name changes;
- stricter network prompts caused by separating approval categories;
- invalidation of any changed Scanner IDs or signed cursors;
- tighter schema handling for explicit null and malformed HTTP/2 input;
- any catalog-wide `isError` behavior change;
- v4.7.0 supersession without changing its old bytes.

## Stable promotion — v4.11.0

The earlier versioned workstreams roll into the v4.11.0 stable candidate. It may be published only after all of the
following are true:

- [ ] No unresolved v4.11 release-blocking P0/P1 issue; an accepted lower risk has an owner, mitigation, expiry, and
  revisit version.
- [ ] Full unit, integration, lifecycle, schema, security, provider, and catalog tests pass.
- [ ] Stable conformance and supported modern sub-behavior tests pass without a new waiver.
- [ ] Native HTTP and embedded stdio client matrices pass.
- [ ] Community and Professional exact-candidate Burp smoke matrices pass.
- [ ] Project-switch, approval-category, large-Scanner, cancellation, EDT, and unload regressions pass.
- [ ] Two isolated builds produce byte-identical JAR and SBOM files.
- [ ] SBOM schema, hashes, dependency relationships, and explicit licenses validate.
- [ ] Required legal, fork, source, checksum, vulnerability report/evidence, and attestation assets validate.
- [ ] The exact draft JAR digest equals the attested smoke-test digest.
- [ ] `release-rc-observation.yml`, dispatched only from protected `release/v4.11`, attests at least 604,800 seconds
  from immutable `v4.11.0-rc.7` publication with complete issue triage, no unresolved release-blocking P0/P1 defect,
  and exact eleven-path RC7-to-observation continuity.
- [ ] The observation head to stable source changes exactly `gradle.properties`, `BappManifest.bmf`,
  `docs/VULNERABILITY_REPORT.md`, and `docs/releases/4.11.0.md`; later `main` work is absent from the release line.
- [ ] The no-rebuild publish job passes a dry run against the draft and is ready to revalidate the tag and exact assets.

### Mandatory publication completion

The release is complete only after:

- [ ] the no-rebuild publish job succeeds without rebuilding or replacing an asset;
- [ ] latest links, checksums, attestations, source identity, and downloads verify from a clean unauthenticated environment;
- [ ] v4.7.0 is marked superseded without moving its tag or replacing an asset;
- [ ] release/run URLs, full SHA, artifact digests, and smoke-record identity are archived.

## v4.9.0 — Analysis and Reusable Workflows

The stable v4.9 release remains sequenced after stable v4.8. Development may proceed on the isolated
`feature/v4.9-workflow-features` branch without moving or replacing any v4.8 tag or draft asset. This milestone is the
reviewed feature-focused exception to the earlier no-catalog-expansion preference.

### Feature 1 — bounded HTTP session-security analysis

`analyze_http_session_security` passively analyzes 1–32 distinct ordered Proxy, Site Map, or Organizer references. It
returns fixed authentication/header-presence signals, value-free cookie attribute/scope/lifetime classifications,
heuristic login/logout/refresh/redirect roles, and known cross-message invariants/variants. Input order is a proposed flow,
not proof of chronology or browser behavior. Analyzer materialization reads no body or authentication value; the existing
v4.8 Site Map stable-ID verification remains byte-compatible and may privately inspect its bounded identity samples.
No raw body, authentication, cookie, redirect, scope, or lifetime value is returned.

### Feature 2 — project-scoped workflow presets

Four common tools save, list, delete, and execute named HTTP metadata-search, WebSocket metadata-search, or HTTP
comparison settings. One strict versioned envelope in project-backed `extensionData()` is capped at 64 entries and
256 KiB. Dedicated definitions contain no project, cursor, stable-reference, connection-ID, traffic/result, raw-message,
or content-predicate fields. Bounded caller-authored labels/host/path criteria are persisted verbatim and must not contain
secrets. Runtime cursors, limits, and comparison references are never persisted. Execution delegates to the existing
services and approvals. No native preset UI, dynamic resource, or subscription is added.

### Feature 3 — planning-only Repeater prompt

`plan_repeater_tests_without_sending` accepts one canonical project-bound HTTP reference plus an optional bounded focus.
It returns instructions for an observed baseline, evidence limits, and at most eight one-variable-at-a-time manual tests.
Prompt retrieval reads no Burp traffic. The instructions explicitly prohibit sending/replay, routing or creating a
Repeater tab, Scanner execution, editor writes, and all mutation tools. A later explicit user action in Burp is required
to execute a plan.

### Public compatibility

The change is additive. Existing tool inputs, resources, templates, prompt names, approvals, transports, and URI formats
remain unchanged. Current catalogs become 24 Community / 31 Professional tools and 4 Community / 5 Professional prompts.
Clients must reconnect and rediscover capabilities after upgrading.

### v4.9.0 gate

- [x] Analyzer count, duplicate, privacy-sentinel, accessor, truncation, approval, cancellation, and project-transition tests pass.
- [x] Preset store, schema, capacity, malformed-data preservation, concurrency, project-boundary, uncertainty, and delegated-execution tests pass.
- [x] Native HTTP and embedded stdio tests advertise the additive catalogs and preserve the planning-only prompt wording.
- [ ] Supported clients prove prompt discovery and produce zero routing, Repeater-tab creation, sending, Scanner, editor, or other mutation under normal and adversarial focus text.
- [ ] Community and Professional exact-candidate Burp smoke cover analyzer mixed sources and preset project save/reopen behavior.
- [ ] Full release, reproducibility, SBOM/legal, conformance, and supported-client gates pass for the exact candidate.

## v4.10.0 — Scale and Demand-driven Client UX

No additional tool family is planned by default. Candidate work is selected from measured operator demand after v4.9.
Development began under the non-release identity `4.10.0-dev.1`; the first release candidate uses `4.10.0-rc.1`
and remains isolated from the immutable v4.9 release candidates.
The first implementation slice removes the
redundant full WebSocket history copy for random-access source lists while retaining a safe sequential-list fallback,
adds 64-record interruption checkpoints to bounded context-menu fallback scans, and commits a clean-tree Java 21
synthetic allocation/accessor diagnostic. Random-access searches capture only the bounded window a call can inspect and
identity-revalidate its inspected slots before output. A 100,000-entry regression bounds an unfiltered one-record page to
six indexed accesses and a scan-limit-exhausting filtered page to 20,004.

The next server slice stamps every admitted request and pending/active session with an internal project generation. A
request that completed its project check before a later transition can no longer reserve or recover a session after the
transition cleanup. The same serialized boundary revokes sessions, streams, and approvals, detaches Scanner work, drops
warm HTTP metadata, and rotates the retained Collaborator client before new admission. Fixed-cardinality project-change
and successful-initialization protocol counters are visible only in the local diagnostics panel; `burp://diagnostics`
keeps its existing serialized contract. Reproducible opt-in scale and lifecycle scripts now enforce exact source/JAR
identity, private evidence, loopback traffic, RSS cutoffs, and disposable-project acknowledgement. These are extension-
side regressions and harness readiness only; live Community/Professional source-acquisition, returned-list stability,
allocation, and unload evidence remains open.

The selected demand-driven UX slice is a local **YOLO mode** button for operators who intentionally want one persistent
master approval bypass. One warning confirmation enables it; disabling it restores the preserved granular policies.
Every approval family audits `yolo_allow`, while authentication, validation, project binding, bounds, emergency
read-only mode, execution-state handling, and separately disabled tool families remain authoritative. The setting stores
no client, project, target, traffic, payload, credential, path, or filesystem value, and MCP clients cannot enable it.

Candidate work:

- run 10k/50k/100k live matrices for Proxy, Site Map, Organizer, WebSocket, Professional Scanner, and context-menu paths;
- run long-duration multi-client session, cancellation, restart, and unload soak tests;
- live-validate the removed WebSocket snapshot copy and interruption behavior under append, clear, unload, and project
  change;
- use the synthetic diagnostics and live fixtures to separate extension allocation/accessor counts from Montoya
  source-list acquisition;
- review local fixed-bucket initialization-protocol and project-change counters without retaining client identity or
  changing the public diagnostics resource;
- validate raw HTTP/2 routing only against an explicitly supported Burp runtime;
- exact-candidate test the local YOLO control in Community and Professional, including warning cancellation, reload,
  disable/rollback, persistence failure, diagnostics, audit, emergency read-only precedence, and project transitions;
- consider validated multi-client setup previews, multi-instance display labels, security-policy profiles, settings
  portability, and expanded accessibility matrices only as separately reviewed milestones.

### v4.10.0 gate

- [ ] 100k and soak runs have reviewed baselines and no unexplained EDT or extension-allocation regression.
- [x] Delayed old-project session reservation/activation is rejected, and initialized project-retained metadata and
  Collaborator state are cleared before new-project admission.
- [x] Disposable loopback WebSocket scale and bounded protocol-lifecycle runners have fail-closed identity, RSS,
  cleanup, and private-evidence contracts.
- [x] The selected YOLO UI feature has an explicit secret, project, filesystem, rollback, and accessibility contract.
- [ ] HTTP/2 behavior is either live-verified or remains explicitly unavailable.

## v4.11.0 — Measured History Freshness and HTTP Activity Correlation

Development began under the non-release identity `4.11.0-dev.1`; the first frozen candidate uses `4.11.0-rc.1`.
The immutable `v4.10.0-rc.1` and `v4.11.0-rc.1` through `v4.11.0-rc.4` tags, drafts, notes, and assets remain unchanged.
Follow-up exact-smoke orchestration and diagnostics work used the non-release `4.11.0-dev.2` identity; surface reduction
used `4.11.0-dev.3`; and bounded performance work used `4.11.0-dev.4`. RC2 froze the reduced surface and performance
contracts, RC3 froze deterministic session-cancellation evidence, RC4 froze schema/result consistency, and RC5 froze
reader correctness and metadata-index coordination. RC6 remains permanently withheld after privacy/cleanup blockers;
immutable RC7 fixes those blockers, preserves the 21/28-tool catalogs, and is the published observation candidate. Work
remains ordered so measurement precedes scheduling and catalog changes.

Milestones:

1. Attribute Proxy, Site Map, Organizer, and WebSocket history work to direct Burp/Montoya source acquisition versus
   extension processing with fixed-cardinality, value-free elapsed-time buckets shown only in the local diagnostics UI.
2. Add constant-time source-change signals only where the pinned Montoya API has mutation-neutral callbacks, while
   retaining bounded anchors and expiry as the freshness authority.
3. Add at most one distinct common read-only `correlate_http_activity` operation after shared metadata and least-data
   resolver seams are proven. Mixed-source similarity must not be presented as identity or chronology.
4. Coordinate bounded metadata refresh and hint validation without holding the state mutex across Montoya acquisition,
   while preserving generation-checked atomic publication, bounded retry, project/mutation barriers, and close
   quiescence. Treat deterministic concurrency tests as extension-side evidence, not Burp latency proof.

The first deliverable changes no MCP tool, prompt, resource, template, cursor, stable-ID, approval, or result schema.
Metrics survive listener restart for the extension lifetime, retain no project/client/filter/reference/traffic value, and
are diagnostic aggregates rather than Burp product benchmarks. This candidate adds only advisory, value-free source
revisions from passive Proxy/Scanner callbacks and approved Organizer attempts. Unit/race validation is complete;
disposable live Community/Professional timing, visibility, project-replacement, and unload evidence remains open, so
complete event-driven freshness is not claimed.

The correlation slice added exactly one common read-only `correlate_http_activity` tool, initially bringing the catalogs
to 25 Community / 32 Professional tools while leaving prompts, resources, URI templates, cursors,
and then-existing result schemas unchanged. It resolves one ordered batch of at most 16 distinct baseline plus 16 distinct
comparison references through existing source approvals and stable-ID checks. It returns only bounded HTTP metadata,
Proxy capture times when available, invocation-local cross-source similarity groups, and a complete deterministic
attack-surface count delta. Caller order and cohort membership do not establish chronology or causality; similarity does
not establish identity or vulnerability evidence, and records are never deduplicated. Correlation results do not retain
or return query strings, fragments, headers, bodies, notes, or raw messages; existing Site Map stable-ID validation may
privately inspect bounded identity samples. Unit/schema validation covers bounds, privacy,
approval denial, cancellation, project replacement, accessor failure, and the intended one-tool catalog increase; exact
Community/Professional live evidence remains open.

The subsequent surface-reduction slice removes `transform_data`, `generate_random_string`,
`get_active_editor_contents`, and `set_active_editor_contents`. Local shell utilities replace the first two; Burp's
editor UI replaces the focus-dependent pair. The resulting catalogs contain 21 Community / 28 Professional tools, while
all prompts, fixed resources, resource templates, and retained tool schemas remain unchanged.

The `4.11.0-dev.4` performance slice reuses invocation-local Proxy/Organizer source views, resolves each represented
source once for ordered batches of at most 32 stable references, keeps all structured-result materialization on the
bounded serialization dispatcher, and moves linear bounded audit JSON encoding outside the audit lock. It changes no
public catalog, stable-ID, approval, project, cancellation, or uncertain-execution contract. Complete per-edition tool
fingerprints and a local/smoke-workflow scenario-identity regression now fail closed on contract drift. Pinned Montoya
Site Map acquisition remains unchanged because the API has no bounded positional lookup. The separately validated
metadata-index coordination change moves acquisition and processing outside the state mutex while preserving
single-builder admission, generation-checked publication, bounded retry, project/mutation barriers, and close drainage.

The initial post-RC1 exact-smoke slice kept every tool, prompt, resource URI, template, and operation schema unchanged. It added
three fixed fields to the existing diagnostics resource: a path-free loaded code-source JAR SHA-256 and saturation-safe
WebSocket-search completed/cancelled totals. The digest is computed off the UI thread and omission fails the harness;
the two value-free outcome counters prove cancellation deltas without exposing full timing metrics. Candidate-bound
scenario records and both edition preflights are required before an all-pass smoke-workflow input can exist.

RC3 added bounded session-lifecycle cancellation, a value-free `webSocketSearchActive` processing barrier, and exact
cancellation evidence. RC4 retains the exact 21-tool Community and 28-tool Professional names while making stable
non-null structured members explicitly serialized and required by output schemas, making project binding and retry
semantics self-contained, and classifying correction-required and Burp accessor failures consistently. Its reviewed
catalog fingerprints intentionally change because descriptions and output schemas change; names and counts do not. RC5
keeps the public surface and dependency inputs unchanged while adding explicit reader-offset correction and
metadata-index coordination, removing external alert/reviewer dependencies, using OSV/npm-only vulnerability evidence,
and binding that normalized evidence directly to the candidate tag.

Explicitly deferred until their entry gates pass: background indexing, parallel Montoya acquisition, resource
subscriptions, per-session scheduling policy, task-per-event reconciliation, WebSocket send support, and additional tool
aliases or families.

### v4.11.0 gate

- [x] RC1 acquisition and extension-processing measurements are fixed-cardinality, local-only, cancellation-safe, and
  left public diagnostics serialization and the pre-correlation catalogs unchanged; post-RC1 harness fields are additive,
  fixed-cardinality, path/value-free, and candidate-gated.
- [ ] Event invalidation is live-validated without retaining or blocking traffic callbacks; unsupported Site Map and
  Organizer listener gaps remain documented.
- [x] Correlation unit/schema validation is bounded, project-bound, read-only, value-limited, and makes no unsupported
  chronology, causality, identity, or vulnerability-evidence claim; exact live validation remains part of the RC gate.
- [x] Metadata refresh and hint builders are independently serialized, slow acquisition/processing runs outside the
  state mutex, publication is generation/project/mutation checked, retry is bounded, and close drains active builders
  plus project/Scope mutation blocks; no Burp wall-clock improvement is claimed without a fresh dual-edition run.
- [x] The exact 11-scenario Community/Professional smoke contract, native HTTP, embedded stdio, cancellation, scale,
  unload, SBOM, conformance, reproducibility, and no-rebuild publication gates passed for immutable RC7. Same-process
  project replacement and deterministic uncertain-operation reconciliation remain outside the release contract rather
  than being represented as passing evidence.
- [ ] RC7 completes the attested 604,800-second public observation window on protected `release/v4.11`, with complete
  issue triage and no unresolved release-blocking P0/P1, before the exact four-path stable promotion is created.
- [x] The release-control track keeps the MCP surface unchanged at 21 Community / 28 Professional tools and allows
  unrelated post-anchor development to continue on `main` without entering v4.11 stable evidence.

## v4.12.0 — Native Utilities, Execution Workflows, and Local Client UX

Development began on advancing `main` under `4.12.0-dev.1`; after the RC3 CI candidate `4.12.0-dev.4` added
[focused header/MIME reads](REBURP_FEATURE_REVIEW.md) under SerialVersion 16.
RC3 has no tag/draft: its fresh OSV preflight reported four build/test dependency coordinates, so tagging was withheld.
`4.12.0-rc.4` (SerialVersion 17) carries those same features forward and adds only defensive
dependency remediation for that gate: Kotlin `2.4.20` (build plugins and runtime stdlib) and test-only Apache
HttpClient5 `5.6.4` / HttpCore5 `5.4.3` (with `httpcore5-h2` `5.4.3`). It adds no request, scan, or execution
capability. Proxy `2.2.1` is embedded through the existing clean-source guard. See [the RC4 fragment](releases/4.12.0-rc.4.md)
and [candidate dependency baseline](../security/README.md). Fresh OSV/npm against the exact committed server/proxy
pair is required before a test tag; that is not a formal publication or protected-workflow attestation.
The initial [RC5 candidate](releases/4.12.0-rc.5.md), SerialVersion 18, added exact HTTP resource-part admission and
cooperative cancellation checkpoints in the existing shared read services without catalog, proxy or dependency changes.
The subsequent audit cleanup replaces decorative server-toggle rendering with a native Swing toggle, removes unused
helpers/DTOs and one test dependency, and preserves runtime dependency versions, proxy and MCP wire contracts. Its
206-coordinate local candidate baseline still requires fresh exact-source vulnerability evidence; the frozen formal
release gates are unchanged. RC4's signed source/tag/assets remain preserved.
The next stable release remains `v4.11.0` on the protected `release/v4.11` lineage. No v4.12 commit may be merged or
cherry-picked into that release branch. RC1 locally increments `SerialVersion` from 12 to 13, but this is not a frozen
release identity: before signing, reconcile it against every same-UUID predecessor, including the non-ancestor v4.11
stable release. The checked-in draft gate still blocks v4.12 until that predecessor bridge is separately reviewed and
pinned. No earlier candidate's vulnerability, smoke, or publication evidence validates RC1.

RC1 adds a native redacted activity table inspired by reburp's activity-log usability, using the existing audit snapshot,
retention, and diagnostics timer rather than recording raw API/target traffic. It also checks Gradle/BApp/JAR version
parity during ordinary builds. RC2 increments the local SerialVersion to 14 without changing RC1's signed identity.
See [the RC2 fragment](releases/4.12.0-rc.2.md) for that immutable candidate's compatibility and outstanding gates.
[RC3](releases/4.12.0-rc.3.md) uses SerialVersion 15, smaller 8 KiB detail previews, compact private cursors, and passive
agent usage guidance. The 24/38 catalog and explicit 256 KiB read cap remain; reconnect to rediscover changed defaults.
A signed test tag and manually staged unpublished draft do not satisfy the protected publication gates. Such a draft
cannot be retrofitted into the one-shot formal pipeline; that requires a successor candidate after the gates are met.

Milestone order:

1. Add a native Swing Client Setup Center for exactly Claude Desktop, Claude Code, VS Code / GitHub Copilot, Cursor,
   and OpenAI Codex together with its bounded Connection Doctor. Previews and clipboard output are token/path-free. Only
   Claude Desktop reuses the existing atomic private installer; the other four remain preview-and-copy only, and manual
   proxy extraction is a separate action. Doctor runs one direct, body-discarding, no-redirect authenticated
   numeric-loopback admission check off the EDT, creates no MCP session, and exposes only closed categorical
   status/evidence; it does not claim a full MCP handshake or third-party client correctness.
2. Add native local workflow-preset management without traffic execution or a new MCP surface.
3. Extend existing `correlate_http_activity` with bounded related-traffic discovery, then extend existing Scanner tools
   with bounded delta behavior. Do not add aliases or new tools for either feature.
4. Run live Burp-backed 10k/50k/100k measurement before any Montoya parallelization or performance claim, and optimize
   only extension-owned measured hotspots.
5. Extend only the two existing request-routing tools with request-only Comparer and Decoder handoff; add no tool alias,
   response/body-part selector, result reader, or automatic follow-up action.

Milestone 1 preserves every MCP tool, prompt, resource, URI, template, schema, capability, and route behavior. The exact
catalog remains 21 Community / 28 Professional. It persists no selected client, probe result, endpoint, credential, or
telemetry; the current token reaches only the explicit Claude installer and a running-listener Doctor request. One
panel-owned bounded worker serializes installation, extraction, and Doctor work, and unload cancellation suppresses late
UI publication. Synthetic 1024x720 light/dark 100/150/200% layout and keyboard/accessibility tests are required, while
supported-client versions, Burp themes, keyboard-only traversal, screen reader, and high-contrast behavior remain live
RC evidence.

Kotlin MCP SDK/protocol modernization remains blocked on authoritative released server support, stable conformance, and
the v5 approval model. Do not add a parallel raw dispatcher or weaken loopback, bearer, Host, Origin, or project gates.

### v4.12.0 milestone 1 gate

Checked source/offline gates below record mocked, wire-contract, and deterministic UI validation only. They are not live
Burp or third-party-client evidence; the corresponding live gate remains explicitly unchecked.

- [x] Exact five-entry preview/catalog, Claude-only write, token-free manual extraction, and scoped clipboard privacy
  tests pass.
- [x] The valid-current-token 400 / stale-token 401 guard pair proves zero pending, active, initialized, or approved MCP
  session change.
- [x] One-worker EDT/cancellation, no-late-publication, responsive layout, keyboard, and accessibility tests pass.
- [x] At the milestone-1 checkpoint, Community and Professional remain exactly 21/28 with unchanged names/fingerprints,
  and Setup Center/Doctor introduce zero tool/resource/schema production diff. Later milestone-3 additive schemas and
  the milestone-4 diagnostics payload are assessed only by their explicit gates below.
- [ ] Real supported-client and Community/Professional Burp validation is recorded before an RC claim.

Milestone 2 adds one native `WorkflowPresetPanel` and a structured editor over the existing three safe preset definition
types. It shares the exact `WorkflowPresetStore` instance used by the four existing MCP preset tools, keeps all project
observation and persistence off the EDT, and owns one bounded worker that is cancelled on unload. The local manager can
refresh, create, update, and delete, but cannot execute a preset, read traffic, or materialize runtime cursor/reference
fields. Invalid raw storage is preserved; a possible write followed by cancellation or project transition is reported as
uncertain and is not retried automatically.

The local management boundary has no dependency on MCP SDK request, transport, or result classes. A future authoritative
released Kotlin SDK migration replaces the wire adapters around this domain boundary rather than introducing a second
preset store, dispatcher, or native model.

### v4.12.0 milestone 2 gate

- [x] Native create/read/update/delete covers HTTP metadata search, WebSocket metadata search, and HTTP comparison
  definitions while exposing no execution control.
- [x] Native and MCP operations share one synchronized store; malformed/unknown/oversized storage is preserved and
  project transitions return no stale list or falsely certain mutation result.
- [x] Preset persistence runs off the EDT, duplicate actions are disabled, and unload suppresses late publication.
- [x] At the milestone-2 checkpoint, Community/Professional remain exactly 21/28 and native preset management adds no
  tool, prompt, resource, URI, template, capability, schema, or route. The later PERF-012 diagnostics-resource payload
  change is assessed only by the milestone-4 gate below.

Milestone 3 first extends the existing `correlate_http_activity` request/result schema rather than registering a tool or
alias. One to four explicit event indices seed at most four host/first-path searches over an already-authorized set of up
to three sources. Each search returns at most 50 metadata-only candidates; explicit references are excluded, candidates
are canonical-reference deduplicated, and at most 16 deterministic matches are appended after both explicit cohorts.
The original baseline/comparison delta remains exact and unchanged by those events. Results report the bounded search
envelope, truncation, fixed relation signals, and deterministic scores, while expressly denying probability, confidence,
identity, chronology, causality, semantic dependence, vulnerability evidence, or complete project enumeration.

The internal related-search projection retains only the reference and bounded relation metadata needed by correlation.
It does not materialize normal search notes, body lengths, auxiliary Proxy/Organizer fields, complete URLs, or query
strings. Existing Site Map stable-ID generation may still inspect its already-documented bounded private identity
samples. The bounded selected references are reacquired through an instance-bound authorization handle and scored
again from current materialized metadata; missing references fail closed and no-longer-qualifying candidates are omitted.
Source approval is performed once over the explicit/discovery union, and project transition, denial, accessor failure, or
cancellation returns no partial timeline. A later runtime-focused slice keeps the four query evaluations independent but
acquires each authorized discovery source list once per correlation invocation. It also places typed tool decoding,
execution, and result encoding behind one bounded dispatcher boundary, removes per-entry WebSocket scan-window wrappers,
and avoids duplicate HTTP-body access and resource-size byte-array copies. Detached session cleanup also reuses one
all-slots-first, concurrent, total-deadline path, and the lifecycle worker is daemonized so an interrupt-insensitive
third-party startup call cannot retain the process after bounded shutdown returns. A follow-up metadata-index refinement
also reuses fingerprints already computed for retained slots when those slots serve as rebuild/append anchors. It
continues to read omitted-range anchors and every warm-validation anchor from the current source. A subsequent internal
consolidation removes orphaned per-source HTTP/Site Map read DTOs and implementations; production tool and resource reads
remain exclusively behind `HttpMessageReadService` and `HttpMessageResolver`, while the retained Site Map file contains
identity helpers only. Configuration-tool registration also delegates project/user export and import to one
`BurpOptionsService` without changing its schemas, approval operations, credential filtering, project checkpoints,
pre-commit cancellation, post-invocation uncertainty, retry guidance, or metadata-index mutation barrier. Scanner cursor
and delta calls now retain only bounded first/last-anchor fingerprints for repeated references to the same issue object
within one call; result-only misses are not retained. Legacy output, cross-call freshness, stable-ID bytes, and
cancellation behavior remain unchanged. These are code-level work/cardinality and maintenance changes, not live Burp
latency or throughput evidence; the 10k/50k/100k gate and prohibition on Montoya parallelization and performance claims
remain unchanged.

### v4.12.0 milestone 3 correlation gate

- [x] Related discovery is limited to four seeds, four searches, 50 returned candidates per search, 200 candidate
  summaries per invocation, and 16 appended events; every limit/truncation condition is represented in the result.
- [x] Explicit references remain globally distinct and excluded from discovery; appended events never change the
  baseline/comparison delta and never imply chronology, causality, identity, semantic dependence, or vulnerability.
- [x] Additional discovery sources are approved once before source acquisition; selected stable references are
  revalidated without another approval; denial/project transition/missing selection returns no partial explicit or
  related output, and internal related search does not materialize private summary fields.
- [x] Community/Professional remain exactly 21/28 with no new tool, alias, prompt, resource, URI, template, capability,
  or route. For this correlation feature, only its existing schema/description changes; the separate PERF-012
  diagnostics-resource payload change is assessed by the milestone-4 gate below.

Milestone 3 then extends Professional `get_scanner_issues` cursor mode without creating a tool or retaining a decoded
baseline. Every successful ordinary cursor page returns a signed process-local `snapshotCursor`. Passing that token as
`sinceSnapshotCursor` scans only the currently visible range appended after its full-list baseline. A bounded delta
continuation freezes the comparison snapshot and returns `nextDeltaCursor`, which is passed back through the same input;
appends after that freeze wait for a subsequent comparison. Delta mode withholds the next `snapshotCursor` checkpoint
until `hasMore` is false so a caller cannot accidentally advance past an undrained range.

This mode returns at most 50 summaries and scans at most 10,000 issues per call. It reports baseline/current/range sizes,
scan/continuation bounds, and fixed false claims for regression, removal/in-place change, and complete history. Existing
first/last stable anchors reject list shrink and boundary reordering, but cannot detect every same-size middle
replacement. The output therefore means only “new matching Scanner issues visible in an append-stable range”; it is not
a complete added/removed/changed diff, proof of a vulnerability regression, or causality evidence. Snapshot and delta
cursors remain signed, project/query-bound, non-persistent, and invalid after their server-lifetime secret changes.

### v4.12.0 milestone 3 Scanner delta gate

- [x] `cursor` and `sinceSnapshotCursor` are mutually exclusive; tampering, server restart, project mismatch, query
  mismatch, shrink, and boundary reorder fail closed before returning issue summaries.
- [x] Delta pagination freezes the comparison size/anchors, scans at most 10,000 and returns at most 50 per call, exposes
  the appropriate continuation even for an empty filtered page, and excludes later appends until the next baseline.
- [x] Summary/delta paths do not materialize detail, remediation, evidence messages, or Collaborator interactions for
  unselected issues; cancellation and final project recheck discard partial output.
- [x] Result language and evidence explicitly deny complete history, removal/change detection, regression, and causality;
  same-size middle replacement tests must remain an acknowledged non-detection rather than a passing diff claim.
- [x] Community/Professional remain exactly 21/28; for Scanner delta, only the existing Professional issue-search
  schema/description changes and no alias, prompt, resource, URI, template, capability, or route is added. The separate
  PERF-012 diagnostics-resource payload change is assessed by the milestone-4 gate below.

Milestone 4 adds measurement plumbing before any performance optimization. It intentionally expands the existing
authenticated `burp://diagnostics` payload from the historical partial projection to all 16 fixed, value-free history
metrics, including elapsed buckets, saturating totals, and maxima. This permits coarse operation/timing inference by an
authenticated diagnostics reader but retains no traffic, source size, project/session identity, filter, cursor, reference,
or credential. It adds no resource, tool, alias, prompt, URI, template, capability, or route.

### v4.12.0 milestone 4 (PERF-012) gate

- [x] The complete fixed 16-metric diagnostics projection, its authenticated timing-inference tradeoff, and its exact
  value-free schema are reviewed and pinned by wire tests.
- [x] Related-correlation and Scanner-delta acquisition/processing regions remain serial and disjoint; quiet snapshots,
  exact phase-attempt cardinality, nonzero useful work, and attributed time not exceeding client wall time fail closed.
- [ ] Aggregate-only mode-0600 Community and Professional evidence covers each applicable 10k/50k/100k stage on a clean
  exact `4.12.0-rc.N` candidate with reviewed disposable-fixture attestation and exact source/JAR/server identity.
- [x] No latency, percentile, throughput, Burp-product benchmark, optimization, improvement, or Montoya parallelization
  claim is made until accepted live rows identify an extension-owned hotspot and bounded before/after evidence exists.

### v4.12.0 milestone 5 native tool handoff gate

The existing `route_raw_http_request` and `route_http_message_from_id` destination enums additionally accept `comparer`
and `decoder`. Both paths keep the 2 MiB request bound, project checks, request-routing approval/audit category, emergency
read-only interlock, and conservative uncertain-execution result. They pass only the selected or patched request bytes to
Burp's native UI. No response bytes, decoded/comparison result, network transmission, background state, or new MCP name is
added. This adopts the useful handoff idea from reburp while retaining this bridge's authenticated stable-reference and
approval boundaries.

- [x] Community/Professional remain exactly 21/28; only the schemas and descriptions of existing routing/shared-result
  tools change, with reviewed catalog fingerprints.
- [x] Service and registered-wire tests cover both destinations on raw and stored-reference paths, approval denial,
  emergency read-only blocking, destination-specific field rejection, and request-only byte handoff.
- [ ] Community and Professional exact-candidate smoke confirms both native tabs receive the intended request and no
  response or network action before this change is release evidence.

### v4.12.0 milestone 6 native utilities and execution gate

This later milestone intentionally supersedes the milestone-5 no-growth checkpoint after the user requested every
previously deferred reburp-derived category. Community adds `rank_http_messages`, `annotate_http_messages`, and
`execute_local_command`. Professional additionally adds four Request Execution Engine lifecycle tools and two Repeater
custom-action Bambda tools. The RC1 catalogs are 24 Community / 37 Professional; prompts, resources, URI templates,
and dependencies remain unchanged.

- [x] Native anomaly ranking accepts only 1–32 canonically distinct stable references, preserves source approval, enforces
  2 MiB request/response and 16 MiB set limits, sorts Burp ordinals, and states that the result is relative rather than
  severity or vulnerability evidence.
- [x] Annotation updates re-resolve 1–16 records and compare notes/highlights inside the shared mutation barrier after
  approval. Project/emergency checks precede each setter; stale state fails closed and partial note/color or batch writes
  return `execution_uncertain` without rollback or automatic retry.
- [x] Professional Request Execution handles support start, bounded live queue, metadata-only status/await, pause, resume,
  cancel, and cancel-and-delete. Each run is capped at 64 cumulative requests and 16 MiB, four retained or
  cleanup-pending runs count against capacity, response content is dropped, and project/extension cleanup attempts
  cancellation without claiming completion prematurely.
- [x] Bambda import/chain and direct/system-shell command execution require a separate disabled-by-default local
  code-execution switch. Bambda state is capped at 32 distinct MCP-imported IDs per extension lifetime, with same-ID
  replacement reusing capacity. YOLO can bypass the per-call prompt but cannot enable that switch; Emergency read-only is
  rechecked adjacent to invocation. Approval/audit never stores source, command, environment, request, or response values.
- [x] Catalog/schema, service, approval denial, canonical identity, aggregate-bound, project-transition, emergency,
  result-retention, generator escaping, and lifecycle tests pass with reviewed RC1 24/37 fingerprints.

RC2 adds bounded evidence/reporting only: strict complete-value JSON selection and runtime-only response keywords extend
existing reads, while Professional adds human-reviewed issue submission from approved existing HTTP references. Its
catalog is 24/38, with prompts/resources/templates and dependencies unchanged. Issue completion does not prove finding
validity or persistence; exact-candidate native keyword and issue read-back smoke remain gates. No event timeline,
subscription, compression framework, or additional send/scan workflow is introduced.
- [ ] Exact-candidate Professional smoke proves Request Execution start/queue/status/control and generated/raw Repeater
  Bambda import/compile/run behavior. Community and Professional smoke prove RankingUtils, live annotations, direct argv,
  system-shell timeout/error behavior, and code-execution toggle/emergency precedence. Use disposable data and commands.
- [ ] Documented acceptance explicitly acknowledges that ShellUtils materializes full output before MCP truncation and
  that imported/auto-running Bambda code, child processes, and already-started native requests are not retroactively
  confined by project switches, outbound policy changes, toggle-off, or Emergency read-only.

## v5.0.0 — Modern MCP gate

There is no target date. [V5_READINESS.md](V5_READINESS.md) and
[V5_APPROVAL_MODEL.md](V5_APPROVAL_MODEL.md) remain authoritative.

A private alpha cannot start until these entry gates are satisfied:

- a stable modern per-request MCP protocol revision;
- an official released Kotlin SDK server transport and request lifecycle;
- an implemented no-transient-cross-request-grant approval model.

Promotion to beta/RC additionally requires modern conformance without a whole-scenario waiver and a working supported
stable-client matrix.

Stable v5 additionally requires:

- request-bound cancellation/progress/shutdown evidence;
- bounded project-aware task/subscription state, or those capabilities remain disabled;
- full Community, Professional, native HTTP, stdio proxy, and supported-client matrices;
- 10k/50k/100k scale and soak evidence;
- the complete independent release gate;
- at least 14 days of RC testing with no unresolved P0/P1 defect.

Do not implement a parallel raw JSON-RPC transport merely to claim draft compatibility.

## Explicitly deferred

The following are not part of v4.8 or v4.9:

- wildcard or remote listener support;
- weakening loopback, bearer, Host, or Origin checks;
- automatic redirect following for reviewed requests;
- automatic retry of an uncertain side effect;
- autonomous crawling or active WebSocket sending outside the explicitly bounded Request Execution/Bambda surfaces;
- resource subscriptions before bounded SDK lifecycle support;
- a custom partial v5 dispatcher beside the official SDK;
- agent-selected or automatically enabled persistent approval;
- dedicated project-traffic, credential, token, raw-message, or stable-reference fields in profiles, presets, exports, or diagnostics;
- multi-client setup/install UI, multi-instance UX, policy profiles, or settings portability in v4.9;
- full Kotlin package-namespace refactoring solely for branding;
- resource-URI instance migration without demonstrated collision requirements;
- alias tools that expand the catalog without a distinct policy or result model;
- replacement of a published tag or executable asset.

## Milestones and issue map

Required machine-readable release-gate labels:

- priority: exactly one of `priority:P0`, `priority:P1`, `priority:P2`
- disposition: exactly one of `gate:release-blocker`, `gate:non-blocking`

Every GitHub issue created during an RC observation window must carry both classifications. The observation and stable
publication workflows fail closed if Issues are disabled, any required label is absent, triage is ambiguous or missing,
or an open release-blocking P0/P1 exists. Other suggested labels remain:

- area: `area:security`, `area:scanner`, `area:api`, `area:runtime`, `area:ui`, `area:release`, `area:legal`,
  `area:performance`, `area:integration`, `area:docs`
- type: `type:bug`, `type:feature`, `type:decision`, `type:chore`
- additional gate: `gate:v5`
- edition: `edition:community`, `edition:professional`

### Milestone: v4.8.0 — Independent Trust Baseline

| ID | Priority | Issue |
| --- | --- | --- |
| `SEC-001` | P0 | Separate request-routing and outbound-network authority |
| `SEC-002` | P0 | Replace Scanner allocation-before-bound paths |
| `SEC-003` | P1 | Close project-transition gaps across read and mutation families |
| `SEC-004` | P1 | Complete credential/error redaction |
| `SEC-005` | P1 decision | Define DNS semantics for persistent hostname approval |
| `API-001` | P1 | JSON Schema and Kotlin explicit-null parity |
| `API-002` | P1 | Catalog-wide structured outcome and `isError` policy |
| `API-003` | P1 | HTTP/2 header namespace and control validation |
| `API-004` | P1 | Shared canonical references and negotiated-version lifecycle matrix |
| `UI-001` | P1 | Owned installer job, EDT chooser, and unload cleanup |
| `UI-002` | P1 | Validated provider snapshot and persisted start-failure state |
| `REL-001` | P0 | Independent name, UUID, vendor, links, and migration notice |
| `REL-002` | P0 | Complete legal/corresponding-source bundle and SBOM license policy |
| `REL-003` | P0 | Immutable-SHA, read-only, independently reproducible build jobs |
| `REL-004` | P0 | Exact-byte smoke evidence, attestation, and no-rebuild publish workflow |
| `REL-005` | P1 | Dirty-proxy rejection and hermetic dependency inputs |
| `TEST-001` | P1 | Community/Professional exact-byte RC and soak evidence |
| `DOC-001` | P1 | Reconcile active roadmap, release claims, and current-version documentation |

### Milestone: v4.9.0 — Analysis and Reusable Workflows

| ID | Issue |
| --- | --- |
| `TOOL-001` | Bounded read-only session-security analyzer |
| `QUERY-001` | Project-scoped saved metadata-search and comparison presets |
| `PROMPT-001` | Client-validated planning-only Repeater test-plan prompt |
| `COMPAT-001` | Exact 24/31 tool and 4/5 prompt discovery matrices |
| `TEST-002` | Community/Professional mixed-source, persistence, and no-mutation smoke |

### Milestone: v4.10.0 — Scale and Demand-driven Client UX

| ID | Issue |
| --- | --- |
| `PERF-001` | 100k live source/context-menu matrix |
| `PERF-002` | Long-duration multi-client lifecycle soak |
| `WS-001` | Remove redundant WebSocket snapshot copy and prove interruption |
| `H2-001` | Live HTTP/2 routing validation in a supported Burp runtime |
| `DIAG-001` | Bounded negotiated-protocol distribution counters |
| `UX-001` | Select one measured client/operator UX problem for separate review |

### Milestone: v4.12.0 — Native Utilities, Execution Workflows, and Local Client UX

| ID | Issue |
| --- | --- |
| `UX-012` | Five-client secret-free Setup Center with Claude-only installer |
| `DIAG-012` | Bounded session-free Connection Doctor with controlled evidence |
| `PRESET-012` | Native local preset manager without MCP catalog growth |
| `CORR-012` | Related-traffic mode on existing correlation tool |
| `SCAN-012` | Delta mode on existing Scanner surface |
| `PERF-012` | Burp-backed measurement before extension-owned optimization |
| `RANK-012` | Explicit-set native anomaly ranking with aggregate byte bounds |
| `ANNOTATE-012` | Stable-reference notes/highlight mutation with stale-state protection |
| `EXEC-012` | Professional Request Execution Engine ownership, lifecycle, and cleanup reservations |
| `BAMBDA-012` | Opt-in Professional Repeater custom-action import and generated chain |
| `SHELL-012` | Opt-in direct/system-shell execution with exact approval preview and bounded MCP output |

### Milestone: v5.0.0 — Modern MCP gate

Create implementation issues only after the external gates are released:

| ID | Gate |
| --- | --- |
| `V5-GATE-001` | Stable modern protocol publication |
| `V5-GATE-002` | Released Kotlin server transport/lifecycle |
| `V5-GATE-003` | Stable conformance and supported clients |
| `V5-SEC-001` | Sessionless approval implementation |
| `V5-TRANSPORT-001` | Private modern endpoint alpha |
| `V5-RC-001` | Full matrix, scale evidence, and 14-day RC |

## Dependencies and ordering

1. Fork name/UUID/vendor decision blocks manifests, UI copy, client setup, legal notices, and release assets.
2. Authorization separation blocks policy profiles and every later active workflow.
3. Scanner ID/output design blocks schema migration notes and stable-ID compatibility decisions.
4. Legal/source asset specification blocks final packaging and release-workflow implementation.
5. Immutable identity blocks reproducible, attested, smoke-tested, no-rebuild publication.
6. Owned installer lifecycle blocks additional automatic client providers.
7. A repeatable Professional test environment blocks every stable release that claims Professional support.
8. Stable protocol/SDK/conformance/client releases block v5 implementation.

Work inside a milestone may proceed in parallel, but its stable release gate is atomic.

## Roadmap change policy

A feature enters a release only when it has:

- a user problem and concrete workflow evidence;
- a named owner and acceptance tests;
- a defined approval/project/data-retention model;
- input, output, work, concurrency, and retained-state bounds;
- Community/Professional and client compatibility impact;
- documentation and migration impact;
- no dependency on weakening a release gate.

If a feature misses the gate, defer the feature rather than weakening the gate or delaying a security correction. Update
this document when priorities change, and record the decision in the affected milestone/issue.
