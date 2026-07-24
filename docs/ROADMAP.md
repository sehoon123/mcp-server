# Burp MCP improvement roadmap

This document separates transport migration work from proposed product changes. New tools should remain explicit,
scoped, auditable, and safe to invoke from an LLM.

## Current transport baseline

- One stateful Streamable HTTP endpoint: `/mcp`
- No deprecated two-endpoint HTTP+SSE route
- Native HTTP clients connect directly
- Stdio-only clients use the proxy embedded in `burp-mcp-all.jar`
- The proxy relays JSON-RPC methods and parameters supported by the pinned SDK, restores sessions after Burp restarts,
  never retries ambiguous arbitrary requests, and sends bounded best-effort DELETE on graceful stdio shutdown
- Numeric-loopback binding, constant-time per-installation bearer authentication, and Host/Origin validation are mandatory
- Request body/header/URI/concurrency and stateful session count/idle lifetime are bounded

## Priority 0 — security and correctness

### 1. Make binding policy explicit

Implemented for the local production mode:

- Accept only `127.0.0.1` or `::1` as bind values; hostname, wildcard, and remote binds fail closed.
- Require a random per-installation bearer token and compare credentials in constant time.
- Validate Host and browser Origin independently, retain SDK DNS-rebinding protection, and apply restrictive response headers.
- Expose token copy/rotation controls and authenticated client examples without logging secrets.
- Bound request metadata/body, concurrent calls, session admission, idle lifetime, and shutdown cleanup.
- Translate Ktor coroutine wrappers around listener bind failures into a bounded `host:port is already in use` error,
  treat cancellation-only transport closure as successful shutdown, and show the loaded extension version prominently.
- Cover occupied-port recovery and start/stop/start reuse with real CIO listener regression tests.
- Preserve the 32-session and 15-minute bounds while reclaiming only inactive disconnected-stream sessions under
  capacity pressure; keep active calls, open streams, and POST-only sessions protected from early displacement.
- Document mcporter's `/mcp`, direct-header, and keep-alive configuration so separate CLI commands reuse one session.

A remote listener remains intentionally unsupported. Any future remote-access mode requires a separately reviewed
authentication, authorization, TLS, and destination design rather than relaxing these controls.

### 2. Add tool safety metadata and a durable audit log

- Apply MCP tool annotations such as read-only, destructive, idempotent, and open-world behavior.
- Keep per-operation approval for outbound requests, Intruder, Scanner, configuration edits, and destructive actions.
- Show the exact normalized target and operation before approval.

Implemented for stable-ID and focused active actions:

- HTTP replay, Repeater/Intruder/Organizer routing, scope mutation, focused Scanner start/cancel, comparison, and
  Collaborator reads carry explicit annotations.
- Approval shows the source reference, immutable destination service, normalized patch or scope/insertion-point summary,
  and exact resulting request where applicable.
- Target scope include/exclude reviews offer an explicit Always Allow policy that stores one boolean, not target or
  project values; validation, project rechecks, mutation serialization, and verification remain mandatory.
- v4.3 adds fixed-category, memory-only session grants for outbound HTTP, request routing, Scope, and each project-data
  source. They retain no target, request, project, or client value and expire with DELETE, idle/pressure eviction,
  listener restart, or Burp shutdown. UI controls clear active grants or restore all persistent policies to prompting.
- Redacted Burp log lines record bounded action metadata without bodies or header values.
- Structured results distinguish `not_started`, `completed`, and ambiguous `uncertain` execution.
- Active Scanner audits reject out-of-scope references and require semantic insertion points; task lookup/cancellation is
  restricted to random IDs created by this extension instance.

Unified raw Repeater/Intruder/Organizer routing uses the shared request-routing approval gate and executes one
destination per call. Configuration imports, task engine state, Proxy Intercept, active-editor reads/writes, and
configuration exports use explicit sensitive-action approval and accurate annotations.

Implemented globally for v2.1.1:

- A central wrapper audits every registered tool with timestamp, one-way session correlation, tool/read-only metadata,
  declared argument field names (never values), approval decisions, duration, result status, and exception type only.
- Audit persistence is asynchronous, bounded to 50–1,000 retained records, a 30-day maximum age, and a 1 MiB ASCII
  JSON document, and has bounded JSONL copy/clear controls. Bodies, header values, credentials, paths, and raw exception messages are excluded.
- An emergency read-only switch rejects every tool not explicitly annotated read-only before its input handler runs.
  It intentionally does not claim to cancel Scanner work already started inside Burp.

### 3. Replace positional history access with stable IDs

Large histories should not be copied into every model response.

Implemented foundation:

- Compact search summaries expose project-scoped HTTP, WebSocket, Organizer, and deterministic Scanner issue IDs.
- One project-scoped `get_http_message` tool resolves Proxy, Site Map, or Organizer references and supports explicit message-part selection and byte-exact base64 reads.
- Unified HTTP search covers Proxy history, Site Map, and Organizer with structured filters and compact references.
- Search cursors are signed, project-bound, query-bound, and preserve append-only snapshot sizes while detecting cleared
  or reordered source boundaries.
- Search results expose Burp's project ID; detail readers can reject identifiers copied from another project.
- Per-call scan, content, result, cursor, URL, note, and byte-slice limits are bounded.
- New read tools return MCP structured content, output schemas, and safety annotations.
- Scanner issue filtering has a bounded compact cursor mode with signed project/query/snapshot cursors while retaining
  legacy offset/count text behavior for existing callers.
- Stable references can be compared through bounded hashes, header variants, first-difference excerpts, and Burp-native
  response-variation attributes.
- An extension-lifetime, project-bounded HTTP metadata index retains at most 5,000 newest records per source and no
  bodies, header/note values, complete URLs, or Montoya objects. Bounded anchors, a 30-second maximum reuse age, explicit
  invalidation, and project-transition clearing make freshness/truncation visible.
- Snapshot generations and a final project/generation check prevent an aggregate from crossing an observed invalidation;
  one bounded rebuild is allowed. MCP Scope and project-option mutations block snapshots and invalidate both before and
  after execution, including cancellation and uncertain completion paths.
- `summarize_http_attack_surface` returns bounded service, method, status-class, MIME, extension, response, and normalized
  path-prefix aggregates from explicitly approved Proxy, Site Map, or Organizer sources.
- The v4 catalog consolidates same-policy transforms, configuration access, global controls, stable-reference routing,
  raw protocol/destination operations, and cross-source HTTP discovery into 26 Professional tools (19 on Community).
  Deprecated v3 aliases are not registered. Each invocation retains one operation or destination, and fixed value-free
  audit classifications preserve operation context.
- `send_raw_http_request` and `route_raw_http_request` use protocol-nested inputs, structured execution state, bounded
  timeout/output, redirect denial, destination-specific approval/audit, and no automatic retry of uncertain outcomes.
- `search_http_messages` supports the bounded conservative regex language while keeping its signed cursor,
  10,000-record, and 32 MiB budgets. Regex always uses the raw path rather than warm metadata hints.
- `search_websocket_messages` replaces the offset-based WebSocket list with project/query-bound signed snapshot cursors,
  50-result and 10,000-record limits, a 32 MiB regex payload budget, and append/stale boundary semantics.
- Individual WebSocket and Scanner issue reads require `projectId` and discard looked-up results after a project
  transition or bounded content materialization race.
- Eligible newest-first metadata-only Proxy and Organizer searches reuse only recent, already-warm, same-size,
  anchor-validated index entries as advisory hints. Every predicted mismatch is rechecked on the current source field and numeric ID. Stale, reordered,
  unindexed, Site Map, text, regex, and oldest-first records fall back to the raw matcher without changing scan, cursor,
  content-budget, or result semantics.

Remaining work:

- Validate raw HTTP/2 routing against an actual supported Burp runtime; HTTP/2-to-Intruder remains rejected until then.
- Validate metadata-index and unified-search performance with an actual large Burp history. Synthetic differential,
  accessor-count, and JFR allocation probes remain regression evidence rather than Burp product latency claims.

### 4. Standardize structured results and errors

Implemented for v4.1:

- Every Professional and Community tool advertises an output schema and returns MCP `structuredContent`; the seven
  formerly text-only configuration, global-control, active-editor, transform, and random-data tools retain bounded
  legacy text for compatibility.
- Those migrated tools share machine-readable status and retry enums for validation, approval denial, disabled or
  unavailable UI state, output limits, Burp failures, and success.
- Configuration, control, and editor mutations report `not_started`, `completed`, or `uncertain`; uncertain failures
  carry `do_not_retry` guidance because the side effect may already exist.
- Utility, configuration, and editor fields and error summaries have explicit output bounds. Invalid oversized input is
  rejected before the operation or side effect begins.

Remaining work:

- Extend common retry metadata to older structured result families where it adds information beyond their existing
  status, execution-state, and error fields without breaking stable schemas.
- Expand recursive credential filtering and test common API-key, cookie, certificate, and authorization formats.

### 5. Make the embedded proxy reproducible

Implemented foundation:

- Build `mcp-proxy` from a pinned source commit and record its commit and SHA-256.
- Verify both the source proxy and the copy embedded in the extension.
- Produce byte-identical proxy and extension JARs from identical inputs.
- Run official lifecycle, ping, tool-list, DNS-rebinding, and concurrent-POST conformance scenarios in CI.

Implemented release controls:

- Deterministic CycloneDX 1.6 SBOM generation covers the extension runtime and the pinned proxy runtime metadata.
- The SBOM task is configuration-cache compatible and verifies the proxy artifact against its recorded SHA-256.
- Releases include the SBOM, dependency vulnerability review, third-party notices, license, and `SHA256SUMS`.
- Matching annotated source tags are published for releases and resolve to the same commit as the release target.
- A manual-only `workflow_dispatch` verifies native HTTP and embedded-stdio clients, runs two clean no-build-cache
  packages, compares JAR/SBOM bytes, generates checksums and provenance attestations, and creates or updates a draft.
  It never publishes a release; live Burp validation and an annotated tag remain explicit release gates.

Remaining work:

- Evaluate signed checksums in addition to GitHub artifact attestations while retaining manual, draft-first publication.

## Priority 1 — use more of MCP

### 6. Expose read-heavy Burp data as resources

Implemented foundation in v4.4.0:

- Advertise fixed `burp://diagnostics`, `burp://project/summary`, and `burp://scope/summary` JSON resources.
- Advertise canonical project-scoped HTTP, WebSocket, and Professional Scanner issue resource templates.
- Reuse the existing source-specific approval gate on every protected read, including bounded session grants.
- Reuse current-project, stable-ID, and post-materialization revalidation rather than treating a URI as authority.
- Return only the first bounded content slice and direct clients to the existing tools for additional byte pagination.
- Relay resources unchanged through the embedded stdio compatibility proxy.

Implemented in v4.4.1:

- An official Montoya context-menu provider copies one canonical project-scoped HTTP, WebSocket, or Professional
  Scanner resource reference without copying raw traffic, credentials, endpoints, or local paths.
- Directly exposed Proxy, Organizer, and WebSocket source IDs are read without scanning. Fallback source matching and
  Scanner issue hashing run on one bounded background worker; project transitions, queue pressure, unsupported contexts,
  and ambiguous matches fail closed.
- Existing v4 URI templates remain unchanged. The MCP connection/configured server name remains the resource namespace;
  a URI-level instance label is deferred until a real multi-server collision demonstrates that a migration is needed.

Implemented in v4.4.2:

- One extension-lifetime Swing EDT watchdog samples queue delay every 500 ms with at most one pending runnable. It exposes
  only fixed delay buckets, a maximum, coalesced probes, and an error count through redacted diagnostics.

Remaining work:

- Validate context-menu behavior and timing against 100,000-record live Site Map and WebSocket histories.
- Evaluate resource subscriptions and list-change notifications only for explicitly selected, policy-safe records.

### 7. Add reusable prompts for common workflows

Implemented foundation in v4.4.0:

- Analyze one selected HTTP reference without sending traffic.
- Compare two stable HTTP references.
- Review authentication and session-handling evidence passively.
- Summarize a Scanner issue without starting or changing a scan (Professional).
- Bound prompt arguments and keep prompt retrieval independent from project-data reads, so protected resources still
  apply their approval checks when the client follows a prompt.

Remaining work:

- Add a minimal Repeater test-plan prompt only after its wording and client behavior can reliably distinguish planning
  from request routing or transmission.
- Validate resource-link rendering and prompt discovery across the supported client matrix.

### 8. Support progress, cancellation, and MCP tasks

Long-running operations should not look like hung calls.

Implemented before v4.5.0:

- Collaborator long polling emits progress, propagates coroutine cancellation, limits concurrent waits, and bounds
  interaction metadata/details.
- Focused Scanner work is asynchronous in Burp and exposes extension-owned start/get/cancel lifecycle tools.

Implemented in v4.5.0:

- HTTP history search, WebSocket history search, and attack-surface preparation emit six monotonic, value-free fixed
  stages when a progress token is supplied. Their bounded loops check cooperative cancellation between record batches;
  internal snapshot retries cannot regress or multiply stages.

Remaining work:

- Connect wire-level `notifications/cancelled` to active handlers when the Kotlin SDK exposes the original request and
  cancellation lifecycle; SDK `0.14.0` does not currently do so.
- Evaluate Montoya `2026.7`'s request-execution lifetime and explicit `cancel()` handle in an isolated matching Burp
  runtime; do not raise the production dependency or minimum Burp version until compatibility is proven. Other Burp
  operations still require their own explicit cancellation lifecycle.
- Use stable MCP tasks for operations that outlive a single HTTP request after the protocol, SDK, and supported clients
  agree on the task lifecycle.
- Distinguish cancellation from timeout and partial completion consistently across every structured result.

### 9. Notify clients when capabilities change

- Advertise `tools.listChanged` when configuration or Burp edition changes the available tool set.
- Emit resource-list changes only after policy or data changes relevant to the connected client.
- Re-negotiate or request a client restart when a change cannot safely be represented in-session.

### 10. Add protocol diagnostics

Implemented incrementally through v4.3.0:

- A local Burp panel shows listener state/endpoint, the production protocol target, request and active/peak call counts,
  pending/active/initialized sessions, idle evictions, admission/authentication rejections, and last activity.
- Copyable diagnostics exclude credentials, traffic, client identifiers, and paths; only a centrally sanitized startup or
  shutdown error can appear.
- The panel reports the embedded proxy version, full source commit, SHA-256, and extraction verification state.
- Fixed-cardinality counters report optional event-stream opens/closes/reopens, liveness ping outcomes, heartbeat failures,
  explicit authenticated DELETE requests, pressure evictions, and aggregate session-approval grant/session counts without
  retaining client or traffic values.

Remaining work:

- Track bounded per-session negotiated protocol distribution without retaining client names or capabilities.
- Add proxy-to-server correlation only if it can remain value-redacted and bounded across reconnects.

## Priority 2 — usability and integrations

Implemented incrementally through v4.3.2:

- The MCP settings viewport tracks the available width instead of silently hiding horizontally oversized content.
- Explanatory text wraps, long action rows stack when required, and the single/two-column breakpoint follows the UI font scale.
- Approval options retain text-fitted single-row choices; persistent Always Allow choices use warning styling and
  explicitly state that they do not expire automatically, while the final denial remains the safe keyboard default.
- Styled buttons, links, and the server toggle expose visible focus and support Enter/Space; fields, toggles, and policy
  controls expose accessible labels or descriptions. Geometry tests cover the 1,024×720 viewport at 100%, 150%, and
  200% UI fonts with light and dark palettes.

Remaining work:

- Validate the complete settings and approval surface in live supported Burp light/dark themes, keyboard-only navigation,
  and OS-level high-contrast modes on each release candidate.
- Add installers and verified examples for Claude Desktop, Claude Code, VS Code/Copilot, Cursor, Codex, and MCP
  Inspector.
- Add named security-policy profiles such as read-only review, scoped active testing, and full local control.
- Support selecting a Burp project or task context so multiple Burp instances cannot be confused.
- Add saved comparison profiles only if repeated workflows justify them; compact stable-ID HTTP comparison is implemented.
- Add saved, scoped history queries and optional notifications instead of model-side polling.
- Provide import/export of MCP settings with secrets excluded by default.

## Current post-v4.5 execution order

This is the active PM order while the modern protocol gates remain closed:

1. Define the sessionless approval baseline and normalize cancellation, timeout, partial-completion, and uncertain results.
2. Run the isolated Montoya `2026.7` compatibility spike without changing the production dependency.
3. Design policy-safe list changes and project-bound resource subscriptions that close on project transition.
4. Complete the supported-client install, discovery, resource-link, prompt, restart, and fallback matrix.
5. Extend common retry metadata and recursive sensitive-value filtering without breaking existing output schemas.
6. Improve multi-instance/project UX, approval/task state, settings portability, and accessibility.
7. Perform the deferred scale and soak work at the v5 RC gate rather than ahead of current feature/security work.

See [V5_READINESS.md](V5_READINESS.md) for release gates and
[V5_APPROVAL_MODEL.md](V5_APPROVAL_MODEL.md) for the sessionless authorization decision.

## Suggested implementation order

| Order | Change | Benefit | Risk/effort |
|---|---|---|---|
| 1 | Unified HTTP search, Site Map reads, project-scoped references | High daily-use and token improvement; implemented | Medium |
| 2 | Stable-ID request mutation and routing to HTTP/Repeater/Intruder/Organizer | High-use workflow; implemented with bounded structured patches and approvals | Medium |
| 3 | Scope query and management | Implemented with normalization, approval, verification, and uncertain partial-state reporting | Low–medium |
| 4 | Focused audit and Scanner task lifecycle | Implemented for passive evidence and explicit active insertion points; crawl remains deferred | High |
| 5 | Structured comparison and Intruder insertion points | Implemented with bounded diff/variation output and semantic selectors | Medium–high |
| 6 | Collaborator waits and bounded interaction reads | Implemented with progress, cancellation, filters, slicing, and concurrency limits | Medium |
| 7 | Body-free metadata index and attack-surface summary | Implemented with project/source/memory/output bounds and advisory warm-search hints | Medium |
| 8 | Cookie/session and active WebSocket lifecycles | Broader authenticated and WebSocket testing | High |
| 9 | Resources and reusable prompts | Native resources/prompts implemented in v4.4.0 and safe context-menu reference copy in v4.4.1; subscriptions remain | Medium |

## v5 protocol gate

Version 5 is reserved for the modern per-request MCP era. The proposed `2026-07-28` protocol is still a draft, Kotlin
SDK server support is not released, modern conformance remains prerelease, and connection-scoped approval grants need a
safe sessionless replacement. Continue v4 production hardening while those gates are open; do not ship a partial raw
transport fork merely to claim draft compatibility. See [V5_READINESS.md](V5_READINESS.md) for the gate matrix and staged
release criteria, and [V5_APPROVAL_MODEL.md](V5_APPROVAL_MODEL.md) for the fail-safe modern approval baseline.

## Design constraints

- Never weaken loopback, Host, or Origin validation merely to make a client connect.
- Never retry an ambiguous state-changing action automatically.
- Treat `executionState=uncertain` as potentially completed and require explicit user reconciliation before another attempt.
- Preserve stable identifiers and explicit scope across every operation.
- Prefer Montoya APIs and MCP SDK capabilities over custom protocols.
- Keep the default installation to one `burp-mcp-all.jar` file.
