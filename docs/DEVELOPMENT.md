# Development guide

This is the contributor guide for the independently maintained `sehoon123/mcp-server` fork. It describes the current
v4 architecture and the engineering rules that new code must preserve. For current version priorities, see
[NEXT_RELEASE_ROADMAP.md](NEXT_RELEASE_ROADMAP.md); for the release pipeline and fork-distribution policy, see
[RELEASING.md](RELEASING.md).

The repository remains derived from PortSwigger's original MCP Server. Keeping an upstream tracking remote is useful,
but changes in this repository are developed, reviewed, and released independently; an upstream pull request is not a
release prerequisite.

## Quick start

### Prerequisites

- JDK 21 or newer to launch Gradle; production bytecode targets Java 21.
- Git.
- Node.js 22 only when running the external MCP conformance tools locally.
- Burp Suite Community or Professional for manual extension testing. Professional is required for Scanner and
  Collaborator paths.

Always use the checked-in Gradle wrapper:

```bash
git clone https://github.com/sehoon123/mcp-server.git
cd mcp-server
./gradlew test
./gradlew embedProxyJar generateSbom
```

Build outputs:

- Extension: `build/libs/burp-mcp-all.jar`
- Test report: `build/reports/tests/test/index.html`
- CycloneDX SBOM: `build/reports/compliance/bom.cdx.json`

A release-like local verification is:

```bash
./gradlew clean test embedProxyJar generateSbom --no-build-cache
```

Run one test class while iterating:

```bash
./gradlew test --tests net.portswigger.mcp.tools.HttpMessageActionsTest
```

### Load the extension in Burp

1. Build `build/libs/burp-mcp-all.jar`.
2. In Burp, open **Extensions → Installed → Add → Java**.
3. Select the JAR and open the **MCP** suite tab.
4. Keep the listener on a numeric loopback address. Do not relax the binding policy to make a container or remote host
   work; remote access needs a separate authentication, authorization, and TLS design.
5. Copy the bearer token from the MCP tab into the test client without placing it in source, command history, logs, or
   screenshots.
6. Disable any other copy of the extension before testing to avoid a listener-port conflict.

For stdio-only clients, use the proxy extracted by the extension. Native Streamable HTTP clients connect directly to
`/mcp`; they do not launch a separate proxy JAR.

## Architecture

```text
Native MCP client ───────────────────────────────┐
                                                 │
Stdio client → embedded mcp-proxy → HTTP /mcp ──┤
                                                 ▼
                                      KtorServerManager
                                   admission/auth/session guard
                                                 │
                                      MCP SDK Server instance
                                   tools / resources / prompts
                                                 │
                                 bounded tool execution wrapper
                                  audit + approval + cancellation
                                                 │
                                        service classes
                                                 │
                                           Montoya API
                                                 │
                                            Burp Suite
```

`ExtensionBase` is the composition root. It creates configuration, durable audit state, the EDT watchdog, the server
manager, provider installers, the Swing tab, and the context-menu provider. Extension unload closes those owners in a
bounded sequence.

`KtorServerManager` owns listener start/stop/restart serialization, request admission, Streamable HTTP sessions, project
epoch alignment, and the MCP SDK `Server`. A listener restart gets a new SDK server, while `ToolServices` retains the
extension-lifetime services that must survive a restart. Project changes revoke sessions/approvals and reset
project-bound state before new-project requests are admitted.

### Source map

| Path | Responsibility |
| --- | --- |
| `src/main/kotlin/net/portswigger/mcp/ExtensionBase.kt` | Extension composition and unload lifecycle |
| `src/main/kotlin/net/portswigger/mcp/KtorServerManager.kt` | Ktor listener, authentication, admission, sessions, project epoch |
| `src/main/kotlin/net/portswigger/mcp/McpResources.kt` | Native resources, templates, prompts, canonical references |
| `src/main/kotlin/net/portswigger/mcp/tools/Tools.kt` | Tool input types and catalog registration |
| `src/main/kotlin/net/portswigger/mcp/tools/McpTool.kt` | Execution dispatcher, audit wrapper, tool/resource registration helpers |
| `src/main/kotlin/net/portswigger/mcp/tools/ToolServices.kt` | Extension-lifetime service ownership |
| `src/main/kotlin/net/portswigger/mcp/tools/*` | Bounded service implementations and result types |
| `src/main/kotlin/net/portswigger/mcp/security/*` | Approval gates, session grants, audit, safe logging |
| `src/main/kotlin/net/portswigger/mcp/schema/*` | JSON Schema derivation and legacy serialization |
| `src/main/kotlin/net/portswigger/mcp/config/*` | Persisted configuration and Swing UI |
| `src/main/kotlin/net/portswigger/mcp/providers/*` | Client configuration and verified proxy extraction |
| `src/test/kotlin/net/portswigger/mcp/*` | Unit, lifecycle, transport, schema, and integration tests |
| `libs/mcp-proxy-all.jar` | Pinned embedded stdio proxy binary |
| `libs/mcp-proxy-source.txt` | Proxy source commit, version, component list, and JAR hash |

## Request and session lifecycle

The production endpoint is one stateful Streamable HTTP route at `/mcp`.

1. Ktor validates bounded request metadata and body size.
2. Numeric-loopback Host/Origin policy and the bearer token are checked.
3. A bounded call lease is acquired.
4. The current Burp project epoch is aligned. A transition revokes old sessions and project-bound work.
5. The SDK creates or resolves a bounded stateful MCP session.
6. `executeRegisteredTool` or `executeRegisteredResource` installs the audit and session-approval contexts.
7. Work runs on `Dispatchers.IO.limitedParallelism(16)`, not on the Ktor event loop or Swing EDT.
8. Explicit DELETE, idle/pressure eviction, project transition, listener stop, or extension unload closes session state.

The epoch guard is an admission boundary, not a substitute for operation-local project checks. A project can change
while an approval dialog, a Montoya call, or result serialization is in progress.

## Adding or changing a tool

### 1. Define a bounded wire contract

Inputs and outputs are Kotlin `@Serializable` classes. The input class name becomes the snake-case MCP tool name, so
renaming it is a wire-breaking change.

Every untrusted string, list, map, integer, byte range, timeout, and cursor must have an explicit bound in schema and at
runtime. Schema validation improves clients but must never be the only runtime defense.

```kotlin
@Serializable
data class ExampleLookup(
    @JsonSchemaMetadata(minLength = 1, maxLength = 256)
    val projectId: String,
    @JsonSchemaMetadata(minLength = 1, maxLength = 128)
    val id: String,
)

@Serializable
data class ExampleLookupResult(
    val status: StandardToolStatus,
    val retry: ToolRetryGuidance,
    val projectId: String?,
    val value: String? = null,
    val error: String? = null,
)
```

Prefer a dedicated service class for Montoya interaction. Keep registration declarative in `registerTools`; do not put a
large implementation in the registration lambda.

### 2. Select accurate tool annotations

Reuse or add annotations in `McpTool.kt`:

- read-only local operation: `READ_ONLY_TOOL_ANNOTATIONS` or `LOCAL_TRANSFORM_TOOL_ANNOTATIONS`
- network request: `HTTP_REQUEST_ACTION_ANNOTATIONS`
- Burp routing without transmission: `REQUEST_ROUTING_TOOL_ANNOTATIONS`
- scope/config/project mutation: a destructive mutation annotation
- Scanner or Collaborator: open-world annotations matching the real side effects

`readOnlyHint`, `destructiveHint`, `idempotentHint`, and `openWorldHint` are security and retry contracts, not UI labels.
Do not mark an action idempotent unless repeating it after an ambiguous response is safe.

### 3. Use the contextual registration helper for new tools

`mcpStructuredToolWithContext` supports bounded progress text, explicit response text, and an explicit `isError` value.
The simpler `mcpStructuredTool` currently emits `isError=false` for every structured result, so using it for a new result
family can create inconsistent client behavior.

Target policy for new and deliberately migrated tools:

| Outcome | `isError` | Retry policy |
| --- | ---: | --- |
| Completed success | `false` | According to operation semantics |
| Invalid argument / stale cursor | `true` | Only after correction or a new search |
| Access or action denied | `true` | Do not bypass the user's decision |
| Project mismatch / not found | `true` | Refresh project/reference state |
| Burp failure before side effect | `true` | Only when result explicitly says safe |
| Execution uncertain | `true` | Never retry automatically; reconcile Burp state |
| Coroutine cancellation | no result | Rethrow `CancellationException` |

Changing existing `isError` behavior is a wire-compatibility change and needs catalog-level tests and release notes.

### 4. Apply the v4.8 target approval model

Treat the MCP client as authenticated but potentially adversarial. Authentication identifies a local client; it does not
authorize project data or side effects. The table below is the required v4.8 target model. The reviewed v4.7 baseline has
the tracked `SEC-001` stable-ID replay exception in [NEXT_RELEASE_ROADMAP.md](NEXT_RELEASE_ROADMAP.md); do not treat the
current implementation as proof that every gate is already independent.

| Capability | Required gate |
| --- | --- |
| Proxy/Site Map/WebSocket/Organizer/Scanner/Collaborator read | `DataAccessSecurity` for that source |
| Any network transmission | `HttpRequestSecurity` for the final service/target |
| Repeater/Intruder/Organizer routing without transmission | `RequestActionSecurity` |
| Exact derived-request review | `RequestActionSecurity`, in addition to any network gate |
| Target scope mutation | `ScopeActionSecurity` |
| Config/control/editor/Scanner lifecycle mutation | `SensitiveActionSecurity` |

Approval categories are orthogonal. A request-routing session grant must not replace outbound-target approval, and data
access must not imply mutation permission. Validate and render the exact normalized action before prompting, then recheck
project and mutable state after the user returns from the dialog.

Session grants retain only fixed categories. Never add request bodies, URLs, target values, project IDs, or client data
to session approval state.

### 5. Bind project-sensitive work to one project

For stable references and project data:

1. Read and validate the requested/current project ID before source access.
2. Perform the source-specific data approval.
3. Resolve references and validate their bounded identity.
4. Recheck the project after every suspending approval and immediately before each side effect.
5. Recheck after lengthy result materialization and before returning success.
6. Return `PROJECT_MISMATCH` and discard data when consistency cannot be proved.

Never return new-project data under an old project ID or old-project data after the authority boundary has moved. The
server epoch guard handles newly admitted calls; in-flight calls still need these checks.

### 6. Enforce bounds before allocation

A response-size cap is insufficient if the implementation first builds an unbounded object or string.

- Inspect counts and byte lengths before calling `toString()`, `getBytes()`, or `Json.encodeToString()`.
- Slice Montoya byte arrays before converting them to text/base64.
- Stop invoking additional getters when a cumulative budget is exhausted.
- Bound both per-record and aggregate bytes, records scanned, results returned, and retained state.
- Apply cheap metadata filters before body sizing or content search.
- Use signed, project/query/snapshot-bound cursors instead of unbounded offset serialization.
- Do not hash an entire attacker-sized detail field merely to produce an identifier; use stable native identity or a
  bounded fingerprint that includes length.
- Keep progress and audit events value-free or strictly redacted.

Large-history APIs may still return a complete Montoya list. Make the extension's additional work bounded and expose
staleness/truncation instead of pretending the source acquisition was constant cost.

### 7. Preserve cancellation and side-effect truth

Catch `CancellationException` before broad exception handlers and rethrow it. Kotlin `runCatching` catches cancellation;
use `runCatchingPreservingCancellation` in suspend-sensitive paths.

For a side effect:

- validate, resolve, and approve before invoking Burp;
- report `not_started` only when the invocation definitely did not happen;
- once a Burp API may have executed, failures become `uncertain` unless completion can be proved;
- include `UNCERTAIN_RETRY_GUIDANCE` and never invite automatic retry;
- audit only bounded metadata, never request bodies or credential values.

### 8. Keep JSON Schema and runtime decoding equivalent

Test the schema as an executable contract, not only as generated JSON structure.

- Optional/nullable fields need explicit tests for absent, non-null, and explicit `null`.
- `required` checks property presence, not non-null value.
- Nullable enums must either include `null` in the allowed values or runtime decoding must reject explicit null.
- `oneOf`/`anyOf` truth tables need a real JSON Schema validator.
- Root-level combinators are constrained by the current Kotlin MCP SDK `ToolSchema`; keep runtime validation and prose
  when a root constraint cannot be represented.
- Input and output schema changes require integration tests through `tools/list` and `tools/call`.

### 9. Register and test the catalog

Register the tool in `Tools.kt`, apply the correct Community/Professional gate, and update exact catalog tests. Add tests
for success, every structured failure status, bounds, cancellation, approval denial, project transition, and edition
gating.

For a source or action family, add at least these regressions:

- session grants do not expand into another approval category;
- project ID changes while approval is suspended;
- project ID changes during result materialization or immediately before mutation;
- over-budget records do not call expensive/unselected getters;
- post-invocation exceptions return uncertain execution;
- explicit JSON null agrees between schema validation and Kotlin decoding;
- audit/error text contains no user values or secrets.

## Resources and prompts

Resources must execute through `executeRegisteredResource` so they receive the same bounded dispatcher, audit context,
and session approval snapshot as tools. Reuse service-layer reads rather than implementing a second authorization path.

Canonical `burp://` references must be validated with the same source-specific parser used by the read service. Prompt
validation must reject a reference that the resource will later reject. Prompt arguments are untrusted text: bound them,
canonicalize identifiers, and quote inserted values as JSON/string literals. Prompts describe actions; they must not
perform hidden side effects.

## Concurrency and Swing

- Create, display, read, and mutate Swing components only on the EDT (`Dispatchers.Swing` or an equivalent synchronous
  EDT bridge).
- Move file I/O, hashing, builds, and Montoya scans off the EDT.
- Split workflows such as file chooser + copy into an EDT selection phase and a bounded background I/O phase.
- Do not use an unowned `kotlin.concurrent.thread` for UI work. Panels that start jobs must own a bounded executor/job,
  disable duplicate actions, and cancel or ignore completion after `cleanup()`.
- Keep listener lifecycle work serialized through `KtorServerManager`; do not start independent Ktor engines.
- State shared across listener restarts belongs in `ToolServices` and must define project reset and extension close.
- Avoid retaining Montoya request/response/project objects in long-lived indexes or global state.

## Testing

### Local suite

```bash
./gradlew test
./gradlew clean test embedProxyJar generateSbom --no-build-cache
```

The test tree includes service-level MockK tests, real CIO lifecycle tests, Streamable HTTP integration tests, stdio proxy
end-to-end tests, security approval tests, schema/catalog tests, provider/config tests, and reproducibility checks in CI.

### External conformance

`runConformanceServer` starts a deterministic test fixture, not a production Burp extension:

```bash
MCP_CONFORMANCE_PORT=19877 ./gradlew runConformanceServer --no-daemon
```

CI invokes pinned stable and modern-alpha conformance packages. If running them manually, copy the exact commands and
versions from `.github/workflows/build.yml`; do not replace pinned versions with `latest`.

The checked-in expected-failure baseline is not permission to ignore additional failures. Add independent passing
coverage for supported behavior and keep each known unsupported behavior as narrow as the conformance runner permits.

### Manual Burp smoke test

Before merging a change that touches Montoya, lifecycle, Swing, or approvals, test the built JAR in the supported Burp
editions:

- start, stop, failed start, and restart;
- native HTTP initialize/list/call/DELETE;
- embedded stdio proxy startup and graceful shutdown;
- approval deny, allow-once, session grant, reset, and persistent-policy reset;
- project switch while a read/action is in progress;
- large history/item behavior and cancellation;
- extension unload during background work;
- diagnostics and audit output for secret/value leakage.

Record the Burp version, edition, OS, JAR SHA-256, commit SHA, client/version, and scenario result.

## Updating the embedded proxy

The proxy is maintained in the companion `sehoon123/mcp-proxy` fork. Never replace `libs/mcp-proxy-all.jar` without
updating and reviewing `libs/mcp-proxy-source.txt`.

Use a clean, trusted proxy checkout. The preflight below fails rather than merely printing a dirty or unexpected
checkout:

```bash
set -euo pipefail
proxy=../mcp-proxy
test -z "$(git -C "$proxy" status --porcelain --untracked-files=all)"
test "$(git -C "$proxy" remote get-url origin)" = "https://github.com/sehoon123/mcp-proxy.git"
git -C "$proxy" rev-parse HEAD
./scripts/update-proxy.sh "$proxy"
./gradlew verifyProxyJar embedProxyJar generateSbom
```

Required review:

- the proxy checkout has no tracked or untracked changes;
- origin is the approved companion repository;
- the recorded full SHA is immutable and reviewed;
- proxy tests passed before the binary was copied;
- source metadata, runtime component list, version, and JAR hash changed together;
- the extension package embeds exactly the verified JAR and provenance text;
- release builds use a fresh detached checkout or worktree rather than relying only on developer discipline.

The helper script currently records `HEAD`; release automation must independently reject a dirty proxy checkout so a
locally modified binary cannot be attributed to an otherwise clean commit.

## Documentation and compatibility

Update documentation in the same change when behavior, bounds, approvals, tool descriptions, schemas, supported clients,
or version claims change.

- `README.md`: user-facing install/configuration and tool behavior
- `docs/DEVELOPMENT.md`: contributor architecture and invariants
- `docs/RELEASING.md`: independent release controls
- `docs/NEXT_RELEASE_ROADMAP.md`: canonical near-term versions, milestones, and release gates
- `docs/PERFORMANCE.md`: measured performance evidence
- `docs/ROADMAP.md`: implemented capability history and long-range backlog
- `docs/V5_READINESS.md`: protocol-migration gates
- `docs/V5_APPROVAL_MODEL.md`: future sessionless approval baseline
- `docs/PROJECT_BOUND_NOTIFICATIONS.md`: project-bound notification design
- `docs/VULNERABILITY_REPORT.md`: release-specific, point-in-time dependency review

Do not copy a previous release's vulnerability report or production-version statement without updating its version,
commit, date, dependencies, and evidence.

## Definition of done

A change is ready for review when:

- the working tree contains no generated or unrelated files;
- input, runtime, output, and retained-state bounds are explicit;
- approval gates and tool annotations match the real operation;
- project and cancellation behavior is tested at suspend/side-effect boundaries;
- side-effect retry semantics are conservative;
- schema validation and Kotlin decoding agree, including explicit nulls;
- UI work follows EDT ownership and background jobs have cleanup;
- audit/log/client errors are bounded and redact complete sensitive values;
- tests, packaging, proxy verification, and SBOM generation pass;
- new dependencies have reviewed integrity and license metadata;
- user/developer/release documentation is updated;
- a live Burp smoke test is recorded when mocks cannot prove the behavior.

Release readiness has additional identity, legal, provenance, reproducibility, and publication gates in
[RELEASING.md](RELEASING.md).
