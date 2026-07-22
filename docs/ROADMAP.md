# Burp MCP improvement roadmap

This document separates transport migration work from proposed product changes. New tools should remain explicit,
scoped, auditable, and safe to invoke from an LLM.

## Current transport baseline

- One stateful Streamable HTTP endpoint: `/mcp`
- No deprecated two-endpoint HTTP+SSE route
- Native HTTP clients connect directly
- Stdio-only clients use the proxy embedded in `burp-mcp-all.jar`
- The proxy relays JSON-RPC methods and parameters supported by the pinned SDK, restores sessions after Burp restarts, and never retries ambiguous arbitrary requests
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
- Redacted Burp log lines record bounded action metadata without bodies or header values.
- Structured results distinguish `not_started`, `completed`, and ambiguous `uncertain` execution.
- Active Scanner audits reject out-of-scope references and require semantic insertion points; task lookup/cancellation is
  restricted to random IDs created by this extension instance.

Legacy raw Repeater/Intruder routing now uses the shared request-routing approval gate. Configuration imports, task
engine state, Proxy Intercept, active-editor reads/writes, and configuration exports use explicit sensitive-action
approval and accurate annotations.

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

- Optional compact summaries expose project-scoped HTTP, WebSocket, Organizer, and deterministic Scanner issue IDs.
- ID lookup tools support explicit message/field selection and byte-exact base64 reads.
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

Remaining work:

- Migrate the remaining legacy source-specific list tools from offset pagination to the signed cursor model. Summary mode
  is now the default for Proxy/WebSocket/Organizer lists; selected previews and pages are bounded and silent mid-JSON
  5,000-character truncation has been removed.
- Use the metadata index for eligible structured-search filters without changing the existing 10,000-record scan,
  signed-cursor, or content-budget behavior. Re-resolve and identity-check every selected source record before details or
  actions, and add lifecycle hooks only where Montoya events make freshness provable.

### 4. Standardize structured results and errors

- Define output schemas for every tool instead of embedding JSON inside text blocks.
- Return machine-readable error codes for approval denial, target rejection, timeout, unavailable Burp features, and
  malformed HTTP.
- Include safe retry guidance and whether an operation might already have executed.
- Bound all outputs and reject oversized input before allocating large buffers.
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

Remaining work:

- Publish matching source tags and evaluate GitHub artifact attestations or signed checksums.

## Priority 1 — use more of MCP

### 6. Expose read-heavy Burp data as resources

Resources can reuse the project-scoped resolver introduced by unified HTTP search and reduce the number of custom tools:

```text
burp://proxy/history/{requestId}
burp://websocket/history/{messageId}
burp://sitemap/{encodedUrl}
burp://scanner/issues/{issueId}
burp://organizer/{itemId}
```

Resource templates and subscriptions can notify clients when an explicitly selected item changes. Sensitive data
checks must run on every read, not only when a URI is listed.

### 7. Add reusable prompts for common workflows

Examples:

- Analyze a selected request without sending traffic.
- Create a minimal Repeater test plan.
- Review authentication and session-handling evidence.
- Summarize a Scanner issue with request/response references.
- Compare two stable message IDs.

Prompts should guide the client to ask for scope and approval; they must not silently launch active testing.

### 8. Support progress, cancellation, and MCP tasks

Long-running operations should not look like hung calls.

- Collaborator long polling emits progress, propagates cancellation, limits concurrent waits, and bounds interaction
  metadata/details. Extend progress to large history searches and other preparation work where it is materially useful.
- Focused Scanner work is asynchronous in Burp and exposes extension-owned start/get/cancel lifecycle tools. Propagate
  cancellation to additional Burp APIs when Montoya provides explicit cancellation handles.
- Use MCP tasks for operations that outlive a single HTTP request.
- Distinguish cancellation from timeout and partial completion.

### 9. Notify clients when capabilities change

- Advertise `tools.listChanged` when configuration or Burp edition changes the available tool set.
- Emit resource-list changes only after policy or data changes relevant to the connected client.
- Re-negotiate or request a client restart when a change cannot safely be represented in-session.

### 10. Add protocol diagnostics

Implemented for v2.1.1:

- A local Burp panel shows listener state/endpoint, the production protocol target, request and active/peak call counts,
  pending/active/initialized sessions, idle evictions, admission/authentication rejections, and last activity.
- Copyable diagnostics exclude credentials, traffic, client identifiers, and paths; only a centrally sanitized startup or
  shutdown error can appear.
- The panel reports the embedded proxy version, full source commit, SHA-256, and extraction verification state.

Remaining work:

- Track bounded per-session negotiated protocol distribution without retaining client names or capabilities.
- Add proxy-to-server correlation only if it can remain value-redacted and bounded across reconnects.

## Priority 2 — usability and integrations

- Add installers and verified examples for Claude Desktop, Claude Code, VS Code/Copilot, Cursor, Codex, and MCP
  Inspector.
- Add named security-policy profiles such as read-only review, scoped active testing, and full local control.
- Support selecting a Burp project or task context so multiple Burp instances cannot be confused.
- Add saved comparison profiles only if repeated workflows justify them; compact stable-ID HTTP comparison is implemented.
- Add saved, scoped history queries and optional notifications instead of model-side polling.
- Provide import/export of MCP settings with secrets excluded by default.

## Suggested implementation order

| Order | Change | Benefit | Risk/effort |
|---|---|---|---|
| 1 | Unified HTTP search, Site Map reads, project-scoped references | High daily-use and token improvement; implemented | Medium |
| 2 | Stable-ID request mutation and routing to HTTP/Repeater/Intruder/Organizer | High-use workflow; implemented with bounded structured patches and approvals | Medium |
| 3 | Scope query and management | Implemented with normalization, approval, verification, and uncertain partial-state reporting | Low–medium |
| 4 | Focused audit and Scanner task lifecycle | Implemented for passive evidence and explicit active insertion points; crawl remains deferred | High |
| 5 | Structured comparison and Intruder insertion points | Implemented with bounded diff/variation output and semantic selectors | Medium–high |
| 6 | Collaborator waits and bounded interaction reads | Implemented with progress, cancellation, filters, slicing, and concurrency limits | Medium |
| 7 | Body-free metadata index and attack-surface summary | Implemented with project/source/memory/output bounds; structured-search integration remains | Medium |
| 8 | Cookie/session and active WebSocket lifecycles | Broader authenticated and WebSocket testing | High |
| 9 | Resources and reusable prompts | More MCP-native API after resolver stability | Medium |

## Design constraints

- Never weaken loopback, Host, or Origin validation merely to make a client connect.
- Never retry an ambiguous state-changing action automatically.
- Treat `executionState=uncertain` as potentially completed and require explicit user reconciliation before another attempt.
- Preserve stable identifiers and explicit scope across every operation.
- Prefer Montoya APIs and MCP SDK capabilities over custom protocols.
- Keep the default installation to one `burp-mcp-all.jar` file.
