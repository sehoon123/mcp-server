# Burp MCP improvement roadmap

This document separates transport migration work from proposed product changes. New tools should remain explicit,
scoped, auditable, and safe to invoke from an LLM.

## Current transport baseline

- One stateful Streamable HTTP endpoint: `/mcp`
- No deprecated two-endpoint HTTP+SSE route
- Native HTTP clients connect directly
- Stdio-only clients use the proxy embedded in `burp-mcp-all.jar`
- The proxy relays JSON-RPC methods and parameters supported by the pinned SDK, restores sessions after Burp restarts, and never retries ambiguous arbitrary requests
- Loopback Host/Origin validation is enabled by default

## Priority 0 — security and correctness

### 1. Make binding policy explicit

The UI currently exposes a bind host, but safe remote access needs more than listening on another interface.

Proposed behavior:

- Keep loopback-only mode as the default and clearly label it.
- Refuse non-loopback binding unless an authenticated mode is enabled.
- Add bearer-token support with constant-time comparison and secret storage through Burp persistence.
- Add an explicit Host/Origin allowlist rather than disabling DNS-rebinding protection.
- Require TLS through a trusted reverse proxy or a configured certificate for remote connections.
- Display the effective endpoint and a prominent warning in the UI.

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

Still required globally: apply the same policy to legacy mutating tools and write a durable, redacted audit format with
client/session correlation and retention controls.
- Record timestamp, client/session, tool, normalized arguments, approval decision, duration, and result status.
- Redact credentials and message bodies according to policy before writing audit records.
- Add an emergency "read-only session" switch.

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

Remaining work:

- Make summary mode the default after a compatibility window and remove silent legacy 5,000-character truncation.
- Migrate the legacy source-specific list tools from offset pagination to the signed cursor model.
- Add event-backed indexes for frequent ID lookups without retaining unbounded message objects.

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

Remaining work:

- Generate an SBOM and dependency vulnerability report for both JARs.
- Publish matching source tags and signed release artifacts.

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

- Show active MCP sessions, negotiated protocol versions, client names, and last activity in the Burp UI.
- Provide a local health/diagnostics panel without exposing sensitive traffic.
- Add configurable structured logging and correlation IDs across stdio proxy and HTTP server.
- Report proxy source version and checksum in diagnostics.

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
| 7 | Cookie/session and active WebSocket lifecycles | Broader authenticated and WebSocket testing | High |
| 8 | Resources and reusable prompts | More MCP-native API after resolver stability | Medium |

## Design constraints

- Never weaken loopback, Host, or Origin validation merely to make a client connect.
- Never retry an ambiguous state-changing action automatically.
- Treat `executionState=uncertain` as potentially completed and require explicit user reconciliation before another attempt.
- Preserve stable identifiers and explicit scope across every operation.
- Prefer Montoya APIs and MCP SDK capabilities over custom protocols.
- Keep the default installation to one `burp-mcp-all.jar` file.
