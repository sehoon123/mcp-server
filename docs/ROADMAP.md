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
- Record timestamp, client/session, tool, normalized arguments, approval decision, duration, and result status.
- Redact credentials and message bodies according to policy before writing audit records.
- Add an emergency "read-only session" switch.

### 3. Replace positional history access with stable IDs

Large histories should not be copied into every model response.

Implemented foundation:

- Optional compact summaries expose project-scoped HTTP, WebSocket, Organizer, and deterministic Scanner issue IDs.
- ID lookup tools support explicit message/field selection and byte-exact base64 reads.
- Per-call limits are bounded and every slice reports its total size and next offset.
- New read tools return MCP structured content, output schemas, and safety annotations.

Remaining work:

- Make summary mode the default after a compatibility window and remove silent legacy 5,000-character truncation.
- Add cursor pagination with deterministic ordering and snapshot semantics.
- Persist a project context identifier so clients can detect IDs from a different Burp project.

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

Resources reduce the number of custom tools and give clients addressable data:

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

- Emit progress for large history searches, Collaborator polling, Intruder preparation, and Scanner operations.
- Propagate cancellation to Burp when the Montoya API supports it.
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
- Add compact request/response diff tools based on stable IDs.
- Add saved, scoped history queries and optional notifications instead of model-side polling.
- Provide import/export of MCP settings with secrets excluded by default.

## Suggested implementation order

| Order | Change | Benefit | Risk/effort |
|---|---|---|---|
| 1 | Stable IDs, field selection, configurable limits | High token and reliability improvement | Medium |
| 2 | Tool annotations, read-only mode, audit log | High safety improvement | Medium |
| 3 | Structured outputs and error taxonomy | Better interoperability | Medium |
| 4 | Reproducible proxy build and SBOM | Supply-chain confidence | Low–medium |
| 5 | Resources for history and issues | More MCP-native API | Medium |
| 6 | Progress, cancellation, and tasks | Better long-operation UX | Medium–high |
| 7 | Authenticated remote mode | Enables remote clients safely | High |

## Design constraints

- Never weaken loopback, Host, or Origin validation merely to make a client connect.
- Never retry an ambiguous state-changing action automatically.
- Preserve stable identifiers and explicit scope across every operation.
- Prefer Montoya APIs and MCP SDK capabilities over custom protocols.
- Keep the default installation to one `burp-mcp-all.jar` file.
