# Active release roadmap

**Status date:** 2026-07-26  
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

No new MCP tool is planned for v4.8.0. User-facing feature work resumes only after the trust baseline is released.

## Release sequence

| Version | Theme | New public capability | Stable gate |
| --- | --- | --- | --- |
| `v4.8.0` | Independent Trust Baseline | None | Security, boundedness, identity, legal, and protected-release gates |
| `v4.9.0` | Operator Safety and Client UX | Policy profiles; client setup/export | No authority expansion; client matrix passes |
| `v4.10.0` | Passive Insight and Scale | One bounded read-only family | Live scale evidence; value-free output |
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

## v4.9.0 — Operator Safety and Client UX

Start this milestone only after v4.8.0 is stable. Prefer configuration and integration improvements over expanding the
tool catalog.

### Feature 1 — named security-policy profiles

Profiles proposed:

- **Read-only review** — local transforms and explicitly approved project reads only;
- **Passive project analysis** — read sources, resources, prompts, and comparisons; no mutation/network action;
- **Scoped active testing** — explicit per-operation network/Scanner/scope approvals with emergency read-only available;
- **Full local control** — exposes all current controls but does not silently enable persistent “Always Allow” policies.

A profile is a reviewed configuration preset, not an authority token. Before applying one, show a permission diff and
which prompts remain mandatory. Agents cannot select or elevate a profile.

### Feature 2 — verified client setup/export

Support the documented matrix for Claude Desktop, Claude Code, VS Code/Copilot, Cursor, Codex, and MCP Inspector.
Prefer a validated preview/copyable snippet before adding automatic file mutation. Automatic installation is allowed only
when path, schema, backup, atomic replacement, permissions, ownership, and rollback are tested for that client/OS.

Bearer values remain separate secrets and must not appear in preview logs, diagnostics, or exported documentation.

### Feature 3 — multi-instance operator UX

Add an optional human-readable instance label to diagnostics and generated client server names. Show endpoint and project
mismatch in the installation preview. Do not use a display label as an authentication principal, approval scope, or URI
authority. Defer resource-URI migration until a real collision requires it.

### Feature 4 — safe settings portability

Add schema-versioned import/export with a diff preview. Exclude bearer tokens, credentials, auto-approved targets, local
paths, traffic, project identifiers, and audit data by default. Sensitive fields require a separate explicit opt-in and
must never be copied through normal support diagnostics.

### Feature 5 — accessibility and discovery matrix

Validate light/dark/high-contrast themes, 100/150/200% UI scaling, keyboard-only navigation, resource links, prompts,
restart, and fallback behavior on every supported OS/client combination.

A planning-only Repeater test-plan prompt may enter v4.9 only after supported clients prove that its wording never routes
or sends a request.

### v4.9.0 gate

- [ ] Profile switching cannot bypass source, project, action, outbound, or emergency-read-only controls.
- [ ] Permission-diff tests cover every profile and persistent policy.
- [ ] Exported settings contain no secret, traffic, project, or local-path value by default.
- [ ] Two Burp instances remain distinguishable without sharing session/approval authority.
- [ ] Every supported client completes discovery, one read, one denied action, and restart/reconnect.
- [ ] Installer/UI lifecycle regressions remain green on supported operating systems.

## v4.10.0 — Passive Intelligence and Scale

Candidate scope is demand-driven. Limit this release to at most one new tool family.

### Candidate capability — bounded session-security summary

A useful read-only addition is a deterministic summary over at most 32 stable HTTP references:

- cookie flags, SameSite, domain/path scope, and lifetime metadata;
- presence—not values—of authentication/session headers;
- redirect, login, logout, refresh, and session endpoint metadata;
- invariant/variant security attributes across selected references;
- explicit missing/oversized/truncated evidence.

It must perform no network request, expose no cookie/header/body value, use source-specific approvals, and recheck the
project before returning. Existing prompts can then interpret a compact structured summary instead of receiving another
full-traffic tool.

### Scale and reliability work

- run 10k/50k/100k live matrices for Proxy, Site Map, Organizer, WebSocket, Professional Scanner, and context-menu paths;
- run long-duration multi-client session, cancellation, restart, and unload soak tests;
- remove redundant full WebSocket snapshot copies and add interruption checks;
- record extension allocation/accessor counts separately from Montoya source-list acquisition;
- add bounded negotiated-protocol distribution diagnostics without retaining client identity;
- validate raw HTTP/2 routing only against an explicitly supported Burp runtime;
- add saved project-scoped query/comparison presets only after repeated real workflows justify persistence.

### v4.10.0 gate

- [ ] The new summary is read-only in annotation and observed behavior.
- [ ] Output, audit, progress, and errors contain no authentication/cookie values.
- [ ] Aggregate record/byte/accessor bounds have adversarial tests.
- [ ] 100k and soak runs have reviewed baselines and no unexplained EDT or extension-allocation regression.
- [ ] Saved workflows, if included, persist no raw traffic or credentials and invalidate at project boundaries.
- [ ] HTTP/2 behavior is either live-verified or remains explicitly unavailable.

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
- project traffic/credentials in profiles, saved queries, exports, or diagnostics;
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

### Milestone: v4.9.0 — Operator Safety and Client UX

| ID | Issue |
| --- | --- |
| `UX-001` | Named security profiles with permission-diff preview |
| `UX-002` | Multi-instance label and collision-safe client naming |
| `INT-001` | Verified setup/export for the supported client matrix |
| `CFG-001` | Secret-free schema-versioned settings import/export |
| `A11Y-001` | Theme, high-contrast, scaling, and keyboard release matrix |
| `PROMPT-001` | Client-validated planning-only Repeater prompt, if evidence permits |

### Milestone: v4.10.0 — Passive Intelligence and Scale

| ID | Issue |
| --- | --- |
| `TOOL-001` | Bounded read-only session-security summary |
| `PERF-001` | 100k live source/context-menu matrix |
| `PERF-002` | Long-duration multi-client lifecycle soak |
| `WS-001` | Remove redundant WebSocket snapshot copy and prove interruption |
| `QUERY-001` | Evidence-gated saved scoped query/comparison presets |
| `H2-001` | Live HTTP/2 routing validation in a supported Burp runtime |
| `DIAG-001` | Bounded negotiated-protocol distribution counters |

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
