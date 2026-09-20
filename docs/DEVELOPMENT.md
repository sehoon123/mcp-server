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
- Burp Suite Community or Professional, with Montoya API build baseline `2026.7`, for manual extension testing. Professional is required for Scanner and
  Collaborator, Request Execution Engine, and Repeater custom-action Bambda paths.

Always use the checked-in Gradle wrapper:

```bash
git clone https://github.com/sehoon123/mcp-server.git
cd mcp-server
./gradlew test
./gradlew embedProxyJar generateSbom
```

Build outputs:

- Extension: `build/libs/independent-mcp-bridge-all.jar`
- Test report: `build/reports/tests/test/index.html`
- CycloneDX SBOM: `build/reports/compliance/bom.cdx.json`

A release-like local verification is:

```bash
./gradlew clean test embedProxyJar generateSbom --no-build-cache
bash scripts/test-release-version.sh
```

`verifyReleaseVersion` rejects Gradle/BApp version drift before tests or packaging. The packaged JAR version is checked
again by `embedProxyJar`; the SBOM version comes from the same Gradle property. This is local consistency validation,
not authorization to bypass the immutable release-line identity or SerialVersion predecessor checks.

Run one test class while iterating:

```bash
./gradlew test --tests net.portswigger.mcp.tools.HttpMessageActionsTest
```

### Load the extension in Burp

1. Build `build/libs/independent-mcp-bridge-all.jar`.
2. In Burp, open **Extensions → Installed → Add → Java**.
3. Select the JAR and open the **MCP Bridge** suite tab.
4. Keep the listener on a numeric loopback address. Do not relax the binding policy to make a container or remote host
   work; remote access needs a separate authentication, authorization, and TLS design.
5. Copy the bearer token from the MCP Bridge tab into the test client without placing it in source, command history,
   logs, or
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
extension-lifetime services that must survive a restart. This includes Request Execution ownership, Bambda/import and
local-command serialization gates, and the workflow-preset repository over the exact project-backed `extensionData()` instance created by `ExtensionBase`; it decodes on each access and does not cache or map
project IDs. Project changes revoke sessions/approvals, cancel or reserve cleanup capacity for extension-owned Request
Execution Engine handles, and reset project-bound state before new-project requests are admitted.

### Source map

| Path | Responsibility |
| --- | --- |
| `src/main/kotlin/net/portswigger/mcp/ExtensionBase.kt` | Extension composition and unload lifecycle |
| `src/main/kotlin/net/portswigger/mcp/KtorServerManager.kt` | Ktor listener, authentication, admission, sessions, project epoch |
| `src/main/kotlin/net/portswigger/mcp/McpResources.kt` | Native resources, templates, prompts, canonical references |
| `src/main/kotlin/net/portswigger/mcp/tools/Tools.kt` | Tool input types and catalog registration |
| `src/main/kotlin/net/portswigger/mcp/tools/McpTool.kt` | Execution dispatcher, audit wrapper, tool/resource registration helpers |
| `src/main/kotlin/net/portswigger/mcp/tools/ToolServices.kt` | Extension-lifetime service ownership |
| `src/main/kotlin/net/portswigger/mcp/presets/*` | Strict project-backed workflow-preset models and synchronized repository |
| `src/main/kotlin/net/portswigger/mcp/tools/*` | Bounded service implementations and result types |
| `src/main/kotlin/net/portswigger/mcp/security/*` | Approval gates, session grants, audit, safe logging |
| `src/main/kotlin/net/portswigger/mcp/schema/*` | JSON Schema derivation and legacy serialization |
| `src/main/kotlin/net/portswigger/mcp/config/*` | Persisted configuration, shared validated `McpEndpoint`, and Swing UI |
| `src/main/kotlin/net/portswigger/mcp/providers/*` | Client configuration, bounded UTF-8 config reads, and verified proxy extraction |
| `src/test/kotlin/net/portswigger/mcp/*` | Unit, lifecycle, transport, schema, and integration tests |
| `libs/mcp-proxy-all.jar` | Pinned embedded stdio proxy binary |
| `libs/mcp-proxy-source.txt` | Proxy source commit, version, component list, and JAR hash |

### Shared endpoint configuration

`McpEndpoint` is the credential-free, immutable endpoint value for listener startup, client previews, installation, and
Connection Doctor. Its factory delegates to `ConfigValidation`, so UI and persisted runtime settings both require a
numeric loopback host and port 1024–65535. Validate the captured startup snapshot before registering tools, reading the
credential, or creating a listener; port zero must never create an undiscoverable ephemeral listener. Keep invalid
endpoints out of diagnostics and route failures through the existing serialized lifecycle.

The Claude installer must validate endpoint and bearer format before proxy extraction or client-file work.
`ClientConfigFile` reads only regular, non-symlinked files, checks size on the opened channel, and additionally bounds the
actual stream read to 4 MiB plus one overflow-detection byte. Preserve strict UTF-8 decoding. Use its bounded streaming
encoder for both merged and default configuration: UTF-8, escaping, and pretty-print growth must fit the same 4 MiB
budget before backup or replacement. Never fully serialize an unbounded string and only then check its length.
An earlier size check is not a bound on a later read, and these checks are not a filesystem transaction against hostile
concurrent directory replacement. See [ARCHITECTURE_REVIEW.md](ARCHITECTURE_REVIEW.md) for this review's scope and retained contracts.

## Request and session lifecycle

The production endpoint is one stateful Streamable HTTP route at `/mcp`.

1. Ktor validates bounded request metadata and body size.
2. Numeric-loopback Host/Origin policy and the bearer token are checked.
3. A bounded call lease is acquired.
4. The current Burp project epoch is aligned. A transition revokes old sessions and project-bound work.
5. The SDK creates or resolves a bounded stateful MCP session.
6. `executeRegisteredTool` or `executeRegisteredResource` installs the audit and session-approval contexts.
7. Work runs on `Dispatchers.IO.limitedParallelism(16)`, not on the Ktor event loop or Swing EDT.
8. Explicit DELETE, idle/pressure eviction, project transition, listener stop, or extension unload closes session state
   and cooperatively cancels registered in-flight tool/resource jobs. Synchronous Burp/Montoya calls remain non-preemptive.

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

### Tool names, titles, and compatibility

Every production tool has a short, sentence-case MCP `title` describing its role. The title is a display label, **not an
alias**: clients must call the exact `name` from `tools/list`. Clients may ignore titles, so the description's opening
verb must agree with the title and remain understandable on its own. Neither a title nor a verb grants permission.

Use this vocabulary for new contracts; retain the existing wire names and schema spellings until a separately reviewed
compatibility migration. Input DTO renaming changes the wire name and is not a metadata cleanup.

| Role | Vocabulary and retained exceptions |
| --- | --- |
| One object, content slice, or status | `get` name / “Read” title. `get_burp_options` returns one configuration object, not a collection. |
| Stored-data discovery | `search` for filtered/content discovery; `list` for enumerating saved definitions (optional type filtering is fine). Historical `get_scanner_issues` has the title “Search Scanner issues”. |
| External interaction observation | “Poll”; historical `get_collaborator_interactions` also supports bounded waiting. |
| Passive interpretation | “Compare”, “Analyze”, “Summarize”, “Correlate”, or “Rank”; preserve each tool's evidence and privacy limits. |
| Local state | “Save”, “Update”, “Set”, “Annotate”, “Delete”, or “Record”. `create_scanner_issue` records an attested finding; it does not verify one. |
| Local routing | Titles explicitly say “Create Repeater tab or route …”; names remain `route_http_message_from_id` and `route_raw_http_request`. No transmission or existing-tab update is implied. Organizer can preserve an unchanged source response, so a stored message is not always request-only. |
| Other side effects | Use the actual action, not a pure-generation label. `generate_collaborator_payload` is “Allocate Collaborator payload”; `generate_bambda_chain` is “Generate and import Repeater Bambda chain”, not a preview. Preserve all approval/execution warnings. |
| Stored passive definition | `execute_workflow_preset` is “Run read-only workflow preset”, not general code or request execution. |

Do not add `_by_id`/`_from_id(s)` to new names merely because an input contains an ID; distinguish the source in the noun
or title when needed. Existing suffixes are compatibility exceptions, not a selector grammar. Read the schema:

- HTTP `ref` is the complete `{source,id}` pair; `refs` is a list of those pairs. Copy IDs as strings, including
  numeric-looking Proxy IDs; do not substitute list offsets. `start_scanner_audit_from_ids` takes `targets`, not bare IDs.
- WebSocket `id` is a numeric message ID, not the `webSocketId` connection ID. Scanner `id` is a versioned opaque string.
  Task/execution operations use their own producing result's `taskId`/`executionId`, never an HTTP reference ID.
- Copy opaque `projectId` from a producing result or `burp://project/summary` when the schema accepts it. HTTP search and
  Scanner issue search capture/recheck the current project internally; neither accepts `projectId`. Project-level Burp
  options also capture/recheck it without returning the ID. User-level options and Burp control state are not project-scoped.
- HTTP content uses `part`; Scanner content uses `field` and conditional `evidenceIndex`. These are not interchangeable.
- New numeric fields should name their unit (`…Bytes`, `…Chars`, `…Ms`, or an explicit record-count name). Existing record
  counts retain `limit`, Scanner `count`, and Collaborator `maxResults`; detail `limit` means **bytes**, not records or
  characters. Existing `Ms`/`Millis` mean milliseconds and `Seconds` means seconds; never rename or convert them silently.

### Tool descriptions are model-facing contracts

MCP tools are model-controlled and clients may rank them with keyword or embedding search over names and descriptions.
The official MCP guidance also recommends clear descriptions, detailed JSON Schema parameter definitions, focused atomic
operations, and brief catalog descriptions to limit context cost. Apply those principles as follows:

- Use this order: action and selection boundary → result → traffic/mutation and approval/project implications →
  uncertain-outcome handling where applicable. Start with the title's action verb and identify the distinguishing source
  or destination; do not bury an import or other mutation behind “generate”.
- Include the operator's task vocabulary for the same operation, because clients rank names and descriptions by keyword
  or embedding similarity. State the Burp-native term and at least one common synonym an agent is likely to use
  (`replay`, `diff`, `Proxy history`, `endpoint inventory`, `vulnerability scan`, `out-of-band`). Synonyms are search
  terms only: they never imply a second callable name and cannot guarantee a client's ranking.
- For a multi-call family, identify the counterpart tools by name in the same entry: a start tool names its status and
  stop tools, and a status or stop tool names the producer of its handle. A client may load only one entry, so the entry
  should say where to continue, though the client still has to load that tool's own definition.
- For overlapping tools, put the selection boundary first: say when to prefer this tool, when to use its raw or
  reference-based counterpart, and whether an already-produced stable reference should be reused instead of searched
  for again.
- Put cross-tool sequencing in the MCP initialize `instructions` field, while keeping each individual description
  self-contained enough for clients that ignore server instructions or load tools selectively. Do not require a read
  step when a later action can consume the producing reference directly.
- For consolidated destination tools, retain the user's task vocabulary (for example, “create a new Repeater tab”)
  and the exact selector (`destination=repeater`). Distinguish new-object creation from updates; a caption is not a
  stable handle. Never describe routing-only tools as connecting to a target or as making no local state changes.
- For sparse optional objects, document omission semantics both on the tool and the property. State whether each call
  starts from a fresh source, whether changes accumulate, and how empty or explicit values differ from omission.
- State network transmission, Burp mutation, routing-only behavior, required approval or access policy, and ambiguous
  execution retry guidance whenever they affect safe tool selection. Tool annotations reinforce these facts but do not
  replace accurate prose.
- Put field-specific formats, conditional requirements, continuation examples, defaults, and bounds in that field's JSON
  Schema `description`. Use exact JSON field names, such as “pass returned `nextCursor` as `cursor`”.
- Keep each catalog description self-contained and concise. The v4 catalog uses a project limit of 512 characters per
  description because clients commonly inject all 24 Community or 38 Professional definitions; this is a project
  convention, not an MCP wire limit.
- Describe observable behavior, not Kotlin, Montoya, compatibility-version, or internal resolver boundaries. Never claim
  that prompt text technically enforces client/model behavior.
- Keep input and output schemas precise enough that the model does not need implementation details in the catalog entry.
  Add an example only when a format or continuation handoff is otherwise ambiguous.

Review descriptions through `tools/list` and prompt descriptions through `prompts/list`. Test both positive contract
phrases and the absence of known misleading wording. Apply the same description, input-property, and annotation checks
in both editions, not only Community. Exercise the named Repeater route without an HTTP send; retain the existing
structured denial/`isError=false` compatibility checks. Initialize guidance and action-result schemas must make clear
that transport-level non-error alone is not success: inspect status and the authoritative side-effect/retry fields.

References: [MCP tools](https://modelcontextprotocol.io/specification/2025-11-25/server/tools),
[MCP server concepts](https://modelcontextprotocol.io/docs/learn/server-concepts),
[MCP client best practices](https://modelcontextprotocol.io/docs/develop/clients/client-best-practices),
[Anthropic tool definitions](https://docs.anthropic.com/en/docs/agents-and-tools/tool-use/implement-tool-use), and
[OpenAI function calling](https://developers.openai.com/api/docs/guides/function-calling).

### Continuation and result interpretation

Keep family-specific continuation rules; a common-looking `limit` or `hasMore` does not imply a common cursor protocol.

| Family | Unit and continuation |
| --- | --- |
| HTTP search | `limit` counts summaries. Pass `nextCursor` as `cursor`, omitting filters or repeating them exactly. |
| WebSocket search | `limit` counts summaries. Cursor calls contain only `projectId`, `cursor`, and optional `limit`. |
| HTTP/WebSocket/Scanner detail | `offset` and `limit` are bytes. Follow the content slice's `nextOffsetBytes` as `offset` while `hasMore`; selected complete JSON/header values are not ordinary byte-preview pages. |
| Scanner issue search | `count` counts issues. Legacy mode advances `offset` by `returned` while `hasMore`; `summariesOnly` does not select cursor mode. Ordinary cursor mode follows `nextCursor`. A fully consumed `snapshotCursor` starts a later `sinceSnapshotCursor` range; `nextDeltaCursor` continues that range. This cannot establish regression, removal, or in-place changes. |
| Preset list | `limit` counts presets. With the same filters, continue at `offset + returned` while `hasMore`. No cursor exists. |
| Preset execution | Follow the selected delegated result's continuation contract, not a fabricated outer cursor. |
| Collaborator interactions | `maxResults` counts interactions; `hasMore` has no continuation cursor. `since` is an exclusive timestamp filter, not a lossless checkpoint (timestamps can tie). `scanLimitReached` leaves unscanned match status unknown. |

An empty search page with `hasMore=true` is not end-of-data. Report incomplete coverage rather than treating bounded,
truncated, access-denied, or unavailable data as evidence of absence.

| Result signal | Interpretation |
| --- | --- |
| MCP `isError` | Tool-level error flag, not a transport-delivery or sufficient success test. Retained direct-read denials can have `isError=false`; preset delegation can classify the same denial as an error. Never use another tool to bypass it. |
| `status` | Operation-specific outcome; read its enum/schema. Action success requires `ok` and a completed side-effect state, not just absence of an MCP error. |
| `executionState` / Scanner `actionState` | Authoritative side-effect outcome (`not_started`, `completed`, `uncertain`). Never automatically retry uncertain mutations. |
| Scanner `taskState` | Separate long-running task lifecycle; a completed status read is not a completed or successful audit. |
| Optional `retry` | Follow it when present; `do_not_retry` wins. Absence is not permission to repeat a mutation, and denial requires user action. |
| Nested results | Preset outer status describes preset lookup; inspect the selected `httpSearch`, `webSocketSearch`, or `httpComparison` status. JSON comparison also requires checking `jsonComparison.status`; `allEqual=null` is incomplete/unavailable, not equality. |
| Detail-read MCP errors | WebSocket/Scanner detail set `isError=true` for `invalid_argument`, `not_found`, `project_mismatch`, and `burp_error`; these are non-mutating reads. |

The catalog tests pin all 38 name/title pairs and opening verbs, units, counterpart links, task-vocabulary terms, and
these audited exceptions; substring presence is all they establish, not ranking or selection quality.
The packaged stdio-proxy test also pins all 24 Community name/title pairs. A separate pre-change contract fingerprint excludes tool titles and schema prose but retains names, properties (including
real fields named `description`), literal defaults, requiredness, enums, bounds, and annotations. Do not update that
fingerprint for a prose-only change; full metadata fingerprints must change and be reviewed. These checks are not a
real-agent selection benchmark, client title-rendering test, or live Burp UI verification.

### Passive response budgets

RC3 uses 8 KiB default HTTP/WebSocket/Scanner detail slices, with explicit limits up to 256 KiB.
Test the matching native resources too: they delegate without an explicit limit. Complete JSON selection is not paginated;
an oversized selected value must fail without a partial result and succeed with an adequate explicit limit.

Keep the structured/text compatibility mirror and public nullable-field schemas intact. This change omits null members
only from private signed cursor JSON, following the existing WebSocket implementation. Retain fixed-key legacy decoding tests when updating
independently generated cursor vectors; HMAC, issuer-key lifetime, query/snapshot binding and all validation stay unchanged.

Existing catalog/read/cursor tests print size-only fixture measurements, never actual project traffic. RC2 → RC3
examples are 66,914 → 17,758 UTF-8 bytes for a mirrored default HTTP preview of a 40 KiB ASCII body,
555 → 386 characters for an HTTP cursor, and 483/470/670 → 391/378/578 for Scanner page/snapshot/delta cursors. These
are synthetic byte/character reductions, not tokenizer counts or real-agent benchmarks. Larger complete-read tasks should
request a sufficient explicit limit instead of incurring extra small-page calls.

RC3's serialized tool arrays were 130,667/197,455 bytes (Community/Professional); focused header/MIME reads and routing
clarifications reached 131,989/198,777. Role titles and compact contract prose now measure 131,876/199,314, including output
schemas. These are serialized byte counts, not tokenizer savings or evidence of better agent selection. Clients differ
in which fields reach a model. Fingerprint tests retain the 132,000/200,000-byte ceilings to make growth deliberate.
Initialize instructions use 1,474 bytes; keep them below 1,500. Include the metadata-only project-summary bootstrap,
reference/project binding, and no-automatic-retry guidance for uncertain or lost mutation results.

### Read cancellation and URI regression checks

Use actual `Job.cancel()` from synthetic native getters, including getters that return normally or throw an ordinary
exception. Assert the service did not return an ordinary result or call later accessors; a cancelled `await()` alone
cannot prove that internal work stopped. Cover pre-cancelled, post-approval/lookup, and final-project-check boundaries.
Do not describe cooperative checkpoints as interruptible native calls or treat service-only tests as proof of a wire leak.
HTTP resource and prompt part validation share exact membership; keep the detail tool's tolerant normalization separate.

### 2. Select accurate tool annotations

Reuse or add annotations in `McpTool.kt`:

- read-only local operation: `READ_ONLY_TOOL_ANNOTATIONS`
- network request: `HTTP_REQUEST_ACTION_ANNOTATIONS`
- Burp routing without transmission: `REQUEST_ROUTING_TOOL_ANNOTATIONS`
- scope/config/project mutation: a destructive mutation annotation
- Scanner, Collaborator, Request Execution Engine, Bambda, or local commands: destructive/open-world annotations matching the real side effects

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
| Repeater/Intruder/Organizer/Comparer/Decoder routing without transmission | `RequestActionSecurity` |
| Exact derived-request review, including stored Request Execution items | `RequestActionSecurity`, in addition to any network gate |
| Target scope mutation | `ScopeActionSecurity` |
| Annotation, Request Execution batch/control, config/control/editor/Scanner lifecycle mutation | `SensitiveActionSecurity` |
| Bambda import or local command | Disabled-by-default `codeExecutionTooling` plus `SensitiveActionSecurity` |

Approval categories are orthogonal. A request-routing session grant must not replace outbound-target approval, and data
access must not imply mutation permission. Validate and render the exact normalized action before prompting, then recheck
project and mutable state after the user returns from the dialog. Comparer and Decoder destinations receive only the
already-bounded request bytes; do not silently add response/body-part selection or return native UI results.

The local **YOLO mode** is the one deliberate master override: after a Burp operator confirms it in the extension UI,
every approval gate records `yolo_allow` and skips its prompt. It must remain off by default, persist-before-publish,
fail closed when enabling cannot be stored, and preserve the granular policies that resume when the operator disables it.
It does not bypass authentication, input and target validation, project checks, operation bounds, emergency read-only
mode, execution-state truth, or separately disabled tool families. The code-execution toggle is rechecked after approval
and adjacent to Bambda/Shell invocation. An MCP tool or client must never enable this mode.

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
staleness/truncation instead of pretending the source acquisition was constant cost. Likewise, ShellUtils returns one
complete native `String`; `outputLimitChars` bounds only the MCP preview and must never be described as a child-process
output or heap cap.

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

## Saved workflow presets

Workflow presets use one strict, versioned JSON envelope in the same Burp project-backed `extensionData()` instance used
by extension configuration and durable audit state. The store synchronizes each decode/read-modify-write operation,
keeps no decoded project cache, caps storage at 64 presets and 256 KiB UTF-8, and preserves malformed, unknown-version,
or oversized raw values. Every operation validates the required current `projectId` before storage and rechecks it
afterward. Once `setString` may have executed, failures and project transitions are reported as uncertain and must not
be retried automatically.

Persist dedicated safe definition DTOs rather than direct tool inputs. Their schema has no project-ID, cursor,
stable-reference, connection-ID, traffic/result, raw-message, content-predicate, credential, or token fields. Bounded
caller-authored name, description, host, and path strings are persisted verbatim and must not contain secrets. Execution must delegate to the existing HTTP search, WebSocket search, or HTTP comparison service, retain
search progress/cancellation, discard delegated output after an unprovable project transition, and add no new approval
category.

The v4.12 native manager and the four MCP tools share the exact same `WorkflowPresetStore` instance. Native list/save/delete
operations recheck the current project and expose only closed local statuses; they never execute a preset or return traffic.
Malformed or unknown storage remains preserved, and a possible write followed by cancellation or a project transition is
`UNCERTAIN` and must be manually reconciled. Native delete confirmation must identify the selected target with a bounded,
control-free preset name and type while omitting the description and saved input values; keep the safe negative action as
the dialog default. Keep `LocalWorkflowPresetManager` independent of MCP SDK request, transport, and result classes: a
future released Kotlin SDK migration should replace only the tool/transport adapters, not fork the persistence,
validation, project-boundary, or Swing-management logic. Do not add dynamic resources, subscriptions, prompts, or catalog
entries for the native manager.

## Resources and prompts

Resources must execute through `executeRegisteredResource` so they receive the same bounded dispatcher, audit context,
and session approval snapshot as tools. Reuse service-layer reads rather than implementing a second authorization path.

Canonical `burp://` references must reuse the source-specific canonical reference builder's validation in both resource
and prompt paths. Reject noncanonical numeric IDs and malformed Site Map IDs before data approval; HTTP resource URI
validation returns `invalid_argument`, while detail tools retain their existing normalization/error contracts. Validation
checks syntax, not record existence, current-project membership, or approval. Prompt retrieval must not read source data.
Prompt arguments are untrusted text: bound them and quote inserted values as JSON/string literals. Keep prompt field names
consistent with `tools/list`: comparison/session analysis use `projectId` and `refs`, not a single `ref`, and references
must not be rebound to a different project. All current prompts are read-only; their shared result builder supplies the
captured-content trust warning, result-status/coverage checks, no-mutation instruction, and prohibition on bypassing a
denial via tools or resources. These are model-facing instructions, not technical enforcement of client behavior.

Test initialization instructions through native HTTP and the embedded stdio proxy, and pass a successful project-summary
result's ID into a read-only tool instead of assuming it. Client setup previews must preserve environment placeholders;
Claude Code project configuration is `.mcp.json`, whereas user-scope registration uses `~/.claude.json`. A local admission
probe, schema test, or substring assertion is not proof that an external client/model follows these contracts.

## Concurrency and Swing

- Create, display, read, and mutate Swing components only on the EDT (`Dispatchers.Swing` or an equivalent synchronous
  EDT bridge).
- Move file I/O, hashing, builds, and Montoya scans off the EDT.
- Split workflows such as file chooser + copy into an EDT selection phase and a bounded background I/O phase.
- Do not use an unowned `kotlin.concurrent.thread` for UI work. Panels that start jobs must own a bounded executor/job,
  disable duplicate actions, and cancel or ignore completion after `cleanup()`.
- `ConfigUi` treats `cleanup()` as a terminal publication boundary: listener-state callbacks arriving afterward must not
  mutate detached controls or open a dialog from the detached panel.
- `ClientSetupPanel` owns one bounded worker for Claude installation, manual proxy extraction, and Connection Doctor.
  Capture host/port and any required credential once on the EDT, run I/O off the EDT, and cancel the panel before server
  shutdown during extension unload so late callbacks cannot publish into disposed UI. Fence each Doctor run with an
  opaque EDT-owned context generation, rotate it after endpoint edits, listener-state transitions, or credential-rotation
  attempts, and publish completion only while the captured generation is still current; the fence must retain no context
  values. Keep `doctorStatusText` independent from installation and proxy-extraction status: client selection and provider
  actions must not rewrite Doctor result/status, while a stale transition must disable evidence copying and publish only
  fixed, value-free Doctor status text.
- `WorkflowPresetPanel` owns a separate single-worker bounded queue. Editor and confirmation snapshots stay on the EDT;
  project observation and persistence run off the EDT. Unload cancels and boundedly drains the worker before server
  shutdown, while every cleanup path suppresses late publication.
- Setup previews must contain only controlled placeholders—never a runtime bearer or resolved user path. After endpoint
  edits, the combined refresh-and-copy action snapshots the displayed endpoint once on the EDT, renders through the same
  safe catalog, and copies exactly the visible preview; validation failure must copy nothing. Only the Claude Desktop
  action may invoke a native client writer; all other client entries remain preview-and-copy only.
- Connection Doctor may read the bearer only when diagnostics report a running listener whose authoritative endpoint
  exactly matches the validated displayed endpoint. Its JDK client must bypass proxy selection, force HTTP/1.1, follow
  no redirects, discard the response body, close after the single request, and expose only closed result enums. Copied
  evidence must retain a fixed, value-free scope marker stating local admission only and external client not tested.
- `AuditActivityPanel` displays only sanitized `McpAuditSink.snapshot()` records. Reuse the diagnostics timer, cap the
  view at the configured retention, keep numeric sorting and literal filtering, preserve selected-record identity across
  refreshes, clear failed snapshots, and suppress reads after cleanup. Do not add traffic getters or another store.
  Bounded JSONL export must retain the newest complete suffix in append order, never the oldest prefix of that snapshot.
  Sanitized audit fields are ASCII, so the 64 Ki-character export cap also bounds UTF-8 bytes. Exact-fit lines need no
  trailing newline; exports never trim persisted records and must not be described as complete history.
- Keep listener lifecycle work serialized through `KtorServerManager`; do not start independent Ktor engines.
- State shared across listener restarts belongs in `ToolServices` and must define project reset and extension close.
- Avoid retaining Montoya request/response/project objects in long-lived indexes or global state.

## Testing

### Local suite

```bash
./gradlew test
./gradlew clean test embedProxyJar generateSbom --no-build-cache
```

On macOS, if the default Java temporary directory includes the `/var` symlink, use a physical temporary path for tests:

```bash
JAVA_TOOL_OPTIONS=-Djava.io.tmpdir=/private/tmp ./gradlew test
```

The private-file tests intentionally reject symlinked ancestors; do not relax the production path guard to accommodate
a temporary-directory alias. Offscreen Swing layout tests explicitly invalidate width-dependent layout caches before
measuring; their clipping assertions still apply at 100%, 150%, and 200% in both themes.

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

Record the Burp version, edition, OS, JAR SHA-256, commit SHA, client/version, and scenario result. For a future exact
release candidate, use the fail-closed preflight, diagnostics-gated read cancellation, dual-edition matrix finalizer, and
cleanup contract in [EXACT_BURP_SMOKE.md](EXACT_BURP_SMOKE.md). Those helpers do not launch or control Burp and cannot
retroactively validate an earlier immutable candidate.

## Updating dependencies and integrity metadata

Runtime and test dependency versions belong in `gradle/libs.versions.toml`. Gradle resolves only locked versions from
`gradle.lockfile` and verifies downloaded artifacts/plugins against `gradle/verification-metadata.xml`. The wrapper
distribution checksum is pinned in `gradle/wrapper/gradle-wrapper.properties`. Conformance npm dependencies are locked
in `.github/conformance/package-lock.json` and installed with lifecycle scripts disabled.

Update these files only from a clean checkout on a trusted network:

```bash
./gradlew dependencies --write-locks
./gradlew --write-verification-metadata sha256 testClasses embedProxyJar generateSbom
npm install --package-lock-only --ignore-scripts --prefix .github/conformance
npm ci --ignore-scripts --prefix .github/conformance
npm audit --audit-level=high --package-lock-only --prefix .github/conformance
```

Review every changed coordinate, repository, checksum, license mapping, npm integrity value, and transitive dependency.
Do not accept a generated verification diff merely because Gradle or npm produced it. After review, verify from an empty
Gradle/npm cache and run the full build. The pinned conformance versions currently have the narrow moderate advisory
waiver documented in `.github/conformance/README.md`; any high or critical finding is release blocking.

## Updating the embedded proxy

The proxy is maintained in the companion `sehoon123/mcp-proxy` fork. Never replace `libs/mcp-proxy-all.jar` without
updating and reviewing `libs/mcp-proxy-source.txt`.

Use a clean, trusted proxy checkout. The preflight below fails rather than merely printing a dirty or unexpected
checkout:

```bash
set -euo pipefail
proxy=../mcp-proxy
test -z "$(git -C "$proxy" status --porcelain --untracked-files=all)"
test "$(git -C "$proxy" remote get-url origin | sed 's/\.git$//')" = "https://github.com/sehoon123/mcp-proxy"
git -C "$proxy" rev-parse HEAD
./scripts/update-proxy.sh "$proxy"
./gradlew verifyProxyJar embedProxyJar generateSbom
```

Required review:

- the proxy checkout has no tracked or untracked changes;
- origin is the approved companion repository;
- the recorded full SHA equals the freshly resolved public `refs/heads/main` tip and is reviewed;
- proxy tests passed before the binary was copied;
- source metadata, runtime component list, version, and JAR hash changed together;
- the extension package embeds exactly the verified JAR and provenance text;
- release builds use a fresh detached checkout or worktree rather than relying only on developer discipline.

The helper serializes updates with an exclusive lock, rejects any origin other than the approved companion fork,
requires local `HEAD` to equal a freshly resolved public `refs/heads/main`, rejects tracked or untracked changes before
and after the build, verifies that neither local nor remote identity moved, validates the nested manifest/legal/runtime
report, builds without cache, and replaces the JAR/source metadata with rollback on a catchable interruption. A hard
process or host failure may leave `libs/.proxy-update.lock` and a deliberately unusable partial pair; inspect the staged
files, restore both tracked files from Git, and remove the lock only after no updater is running. Release review must
still confirm the recorded commit and reproduce the resulting checksum from a fresh detached checkout.

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
source-commit marker, date, dependencies, and evidence. The immutable draft workflow injects the resolved commit only
into the staged report to avoid a self-referential source commit.

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
