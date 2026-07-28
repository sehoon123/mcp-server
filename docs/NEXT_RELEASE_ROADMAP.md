# Active release roadmap

**Status date:** 2026-07-28<br>
**Baseline:** `v4.7.0` / `a1579834995d90be62c269b0b602e6c789bf3a14`  
**Planning model:** gate-based; versions have no promised calendar date

This is the canonical near-term release plan for the independently maintained `sehoon123/mcp-server` fork. The longer
[ROADMAP.md](ROADMAP.md) remains the capability history and long-range backlog. If the two documents conflict, this
active roadmap controls release priority.

## Product decision

The next public release should be **v4.8.0 — Independent Trust Baseline**, not v4.7.1.

The required work is larger than a patch:

- network and request-routing approval semantics change;
- bounded Scanner behavior and stable identifiers may change;
- JSON Schema and MCP error contracts are tightened;
- the extension gets an independent fork identity, UUID, vendor, and support links;
- legal/source artifacts and the release pipeline change;
- existing installations may need explicit migration.

`v4.7.0` should be marked superseded after v4.8.0 is available. Its tag and published assets must not be moved or
replaced. Start public validation at `v4.8.0-rc.1`; do not publish another locally assembled corrective artifact.

No new MCP tool is planned for v4.8.0. Stable v4.9 remains sequenced after the trust baseline; approved feature work
may proceed earlier only on the isolated v4.9 branch without changing any v4.8 tag, draft, asset, or release claim.

## Release sequence

| Version | Theme | New public capability | Stable gate |
| --- | --- | --- | --- |
| `v4.8.0` | Independent Trust Baseline | None | Security, boundedness, identity, legal, and protected-release gates |
| `v4.9.0` | Analysis and Reusable Workflows | Session analyzer; project presets; planning-only Repeater prompt | Exact catalogs, project persistence, no-mutation client matrix |
| `v4.10.0` | Scale and Demand-driven Client UX | No default catalog expansion | Live scale evidence; separately reviewed UX scope |
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
- ensure a session grant for Repeater, Intruder, or Organizer never grants network transmission;
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
- previous-tag selection walks exact SemVer tags on first-parent history, release-note fragments are source-reviewed, the
  change range cannot be empty, and every staged asset is bound to source/JAR/SBOM identity;
- pinned CycloneDX 1.6 schemas plus a locked Ajv validator check the SBOM before the exact hash/dependency/license policy;
- `build.yml` uses the same npm lockfile and uploads a staged, exact identity/legal asset set;
- the Gradle wrapper distribution checksum, dependency locks, and artifact/plugin verification metadata are checked in
  and must be reviewed with any dependency update.

Remaining gate: protected tag/environment configuration, authenticated Dependabot evidence for the signed candidate,
attested exact-byte Burp smoke evidence, the minimal protected publication workflow, and clean post-publication
verification.

Required work:

- resolve one immutable full source SHA and use it in every job;
- run all source builds/tests with read-only permissions and `persist-credentials: false`;
- split build, validation, attestation/draft, protected smoke evidence, and publication;
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
- the protected smoke record includes tag, source SHA, JAR digest, tester identity, environment, and all scenario results;
- the publish job verifies the tag, checksums, attestations, smoke record, and exact files immediately before publication;
- protected branch/tag/environment settings are captured in the release audit record;
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

### v4.8.0 pre-publication gate

A stable candidate may be published only after all of the following are true:

- [ ] No unresolved v4.8 release-blocking P0/P1 issue; an accepted lower risk has an owner, mitigation, expiry, and
  revisit version.
- [ ] Full unit, integration, lifecycle, schema, security, provider, and catalog tests pass.
- [ ] Stable conformance and supported modern sub-behavior tests pass without a new waiver.
- [ ] Native HTTP and embedded stdio client matrices pass.
- [ ] Community and Professional exact-candidate Burp smoke matrices pass.
- [ ] Project-switch, approval-category, large-Scanner, cancellation, EDT, and unload regressions pass.
- [ ] Two isolated builds produce byte-identical JAR and SBOM files.
- [ ] SBOM schema, hashes, dependency relationships, and explicit licenses validate.
- [ ] Required legal, fork, source, checksum, vulnerability-report, and attestation assets validate.
- [ ] The exact draft JAR digest equals the protected smoke-test digest.
- [ ] `v4.8.0-rc.1` or later completes at least seven days without an unresolved release-blocking P0/P1 defect.
- [ ] The protected publish job passes a dry run against the draft and is ready to revalidate the tag and exact assets.

### v4.8.0 mandatory publication completion

The release is complete only after:

- [ ] the protected publish job succeeds without rebuilding or replacing an asset;
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
The immutable `v4.10.0-rc.1` tag, draft, notes, and assets remain unchanged. Work remains ordered so measurement
precedes scheduling changes and catalog growth.

Milestones:

1. Attribute Proxy, Site Map, Organizer, and WebSocket history work to direct Burp/Montoya source acquisition versus
   extension processing with fixed-cardinality, value-free elapsed-time buckets shown only in the local diagnostics UI.
2. Add constant-time source-change signals only where the pinned Montoya API has mutation-neutral callbacks, while
   retaining bounded anchors and expiry as the freshness authority.
3. Add at most one distinct common read-only `correlate_http_activity` operation after shared metadata and least-data
   resolver seams are proven. Mixed-source similarity must not be presented as identity or chronology.
4. Consider bounded single-flight refresh admission only after disposable 10k/50k/100k evidence shows repeated
   same-generation acquisition and proves the required Montoya calls safe on one extension-owned worker.

The first deliverable changes no MCP tool, prompt, resource, template, cursor, stable-ID, approval, or result schema.
Metrics survive listener restart for the extension lifetime, retain no project/client/filter/reference/traffic value, and
are diagnostic aggregates rather than Burp product benchmarks. This candidate adds only advisory, value-free source
revisions from passive Proxy/Scanner callbacks and approved Organizer attempts. Unit/race validation is complete;
disposable live Community/Professional timing, visibility, project-replacement, and unload evidence remains open, so
complete event-driven freshness is not claimed.

This candidate also adds exactly one common read-only `correlate_http_activity` tool, bringing the candidate catalogs
to 25 Community / 32 Professional tools while leaving prompts, resources, URI templates, cursors,
and existing result schemas unchanged. It resolves one ordered batch of at most 16 distinct baseline plus 16 distinct
comparison references through existing source approvals and stable-ID checks. It returns only bounded HTTP metadata,
Proxy capture times when available, invocation-local cross-source similarity groups, and a complete deterministic
attack-surface count delta. Caller order and cohort membership do not establish chronology or causality; similarity does
not establish identity or vulnerability evidence, and records are never deduplicated. Correlation results do not retain
or return query strings, fragments, headers, bodies, notes, or raw messages; existing Site Map stable-ID validation may
privately inspect bounded identity samples. Unit/schema validation covers bounds, privacy,
approval denial, cancellation, project replacement, accessor failure, and the intended one-tool catalog increase; exact
Community/Professional live evidence remains open.

Explicitly deferred until their entry gates pass: background indexing, parallel Montoya acquisition, resource
subscriptions, per-session scheduling policy, task-per-event reconciliation, WebSocket send support, and additional tool
aliases or families.

### v4.11.0 gate

- [x] Acquisition and extension-processing measurements are fixed-cardinality, local-only, cancellation-safe, and leave
  public diagnostics serialization and the pre-correlation catalogs unchanged.
- [ ] Event invalidation is live-validated without retaining or blocking traffic callbacks; unsupported Site Map and
  Organizer listener gaps remain documented.
- [x] Correlation unit/schema validation is bounded, project-bound, read-only, value-limited, and makes no unsupported
  chronology, causality, identity, or vulnerability-evidence claim; exact live validation remains part of the RC gate.
- [ ] Single-flight scheduling remains absent unless its live entry gate and project-cleanup bound pass.
- [ ] Exact Community/Professional, native HTTP, embedded stdio, project-transition, cancellation, scale, unload, SBOM,
  conformance, and reproducibility gates pass for a new immutable v4.11 candidate.

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
- autonomous crawling, exploit chains, or active WebSocket sending;
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

Suggested labels:

- priority: `priority:P0`, `priority:P1`, `priority:P2`
- area: `area:security`, `area:scanner`, `area:api`, `area:runtime`, `area:ui`, `area:release`, `area:legal`,
  `area:performance`, `area:integration`, `area:docs`
- type: `type:bug`, `type:feature`, `type:decision`, `type:chore`
- gate: `gate:release-blocker`, `gate:v5`
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
| `REL-004` | P0 | Protected smoke evidence, attestation, and publish workflow |
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
5. Immutable identity blocks reproducible, attested, smoke-tested, protected publication.
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
