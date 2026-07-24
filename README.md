# Burp Suite MCP Server Extension

Integrate Burp Suite with AI clients through the Model Context Protocol (MCP).

This fork of [PortSwigger/mcp-server](https://github.com/PortSwigger/mcp-server) uses the modern **Streamable HTTP**
transport exclusively. Ordinary calls use JSON over `POST /mcp`; the same endpoint retains Streamable HTTP's optional
`GET /mcp` event stream for server-initiated messages. The deprecated two-endpoint HTTP+SSE server has been removed.

## Distribution and architecture

End users install one file:

```text
burp-mcp-all.jar
```

The extension contains both the Burp MCP server and an embedded stdio compatibility proxy:

```text
Streamable HTTP client ───────────────────────> Burp /mcp
stdio-only MCP client ──> embedded proxy ─────> Burp /mcp
```

The proxy is extracted automatically only for clients that require stdio. It communicates with Burp through
Streamable HTTP, so users do not need to download or install a second component.

### Transport terminology and lifecycle

The optional `GET /mcp` response uses the SSE media format **inside Streamable HTTP**. It is not the obsolete legacy
SSE transport, which used a long-lived `/sse` endpoint plus a separate `/messages` endpoint; both legacy paths return
`404`. Clients can use `POST /mcp` alone for ordinary calls, while a compliant event stream enables progress,
notifications, sampling, elicitation, and other server-initiated protocol messages.

Native HTTP clients should reuse a session and terminate it with authenticated `DELETE /mcp` when they shut down. The
embedded stdio proxy does this automatically on graceful EOF or process shutdown, with a bounded retry for transient
termination failures. An abrupt process kill cannot run graceful cleanup, so the server retains bounded idle,
client-liveness, and capacity-pressure safeguards.

## Features

- Single Streamable HTTP endpoint at `/mcp`
- Automatic Claude Desktop configuration through the embedded stdio proxy
- v4 compact catalog: 26 tools on Professional and 19 on Community, with an output schema and structured content on every tool
- MCP-native read-only resources and reusable prompts, relayed by both native HTTP and the embedded stdio proxy
- Unified HTTP/1.1 and HTTP/2 send/routing tools with target or request-routing approval controls
- Unified compact HTTP search across Proxy history, Site Map, and Organizer with signed snapshot cursors
- Fixed-stage MCP progress and cooperative cancellation checks for bounded HTTP/WebSocket searches and attack-surface preparation
- Body-free, project-bounded HTTP metadata indexing and aggregate attack-surface summaries
- Proxy, WebSocket, Organizer, Site Map, and Scanner summaries with stable IDs and bounded detail reads
- Project-scoped request replay and structured mutation from stable IDs, with Repeater, Intruder, and Organizer routing
- Explicit Target scope checks/updates and bounded HTTP message comparison from stable references
- Focused passive or insertion-point-limited active Scanner audits with extension-owned task status/cancellation (Professional)
- Bounded Collaborator long polling with progress, cancellation, timestamp filtering, and detail slicing (Professional)
- Project and user configuration tools with recursive API-key, token, Cookie, authorization, and certificate/private-key filtering
- Live redacted diagnostics including event-stream, liveness, explicit-termination, and pressure-eviction counters;
  a bounded persistent audit trail; and an emergency read-only switch
- URL/Base64 utilities and random data generation
- Browser-client CORS support and SDK DNS-rebinding protection

## Compact tool catalog

Version 3 consolidated operations only when they shared the same MCP safety classification and preserved one side effect
per invocation. Removed names were not advertised as aliases because aliases would defeat the bounded catalog.

| v2 tools | v3 tool |
|---|---|
| `url_encode`, `url_decode`, `base64_encode`, `base64_decode` | `transform_data` with `operation` |
| `output_project_options`, `output_user_options` | `get_burp_options` with `level` |
| `set_project_options`, `set_user_options` | `set_burp_options` with `level` |
| `set_task_execution_engine_state`, `set_proxy_intercept_state` | `set_burp_control_state` with `control` and `enabled` |
| `get_http_message_by_id`, `get_organizer_item_by_id`, `get_sitemap_message_by_id` | `get_http_message` with `projectId` and `ref` |
| `create_repeater_tab_from_id`, `send_to_intruder_from_id`, `send_to_organizer_from_id` | `route_http_message_from_id` with one `destination` |
| The three `*_regex` list tools | Optional `regex` on their corresponding base list tool |

Source-specific data approval, project and stable-ID validation, request-routing approval, metadata-index invalidation,
and bounded output rules remain in force. Persistent audit approvals use fixed operation classes rather than storing enum
or other argument values.

### v4 catalog

Version 3.1 provided one compatibility window for seven deprecated v3 names. Version 4 removes those names and replaces
the offset-based WebSocket list with `search_websocket_messages`. The current catalog contains 19 Community tools:

| Removed v3 names | v4 replacement |
|---|---|
| `send_http1_request`, `send_http2_request` | `send_raw_http_request` with exactly one protocol-matching nested input |
| `create_repeater_tab`, `create_repeater_tab_http2`, `send_to_intruder` | `route_raw_http_request` with exactly one destination |
| `get_proxy_http_history`, `get_organizer_items` | `search_http_messages` with one selected source and optional safe `regex` |
| `get_proxy_websocket_history` | `search_websocket_messages` with a signed snapshot cursor |

The common catalog is `send_raw_http_request`, `route_raw_http_request`, `transform_data`, `generate_random_string`,
`get_burp_options`, `set_burp_options`, `search_http_messages`, `summarize_http_attack_surface`, `check_scope`,
`update_scope`, `compare_http_messages`, `get_http_message`, `send_http_request_from_id`,
`route_http_message_from_id`, `search_websocket_messages`, `get_websocket_message_by_id`,
`set_burp_control_state`, `get_active_editor_contents`, and `set_active_editor_contents`.

Burp Professional adds seven tools: `get_scanner_issues`, `get_scanner_issue_by_id`,
`start_scanner_audit_from_ids`, `get_scanner_audit`, `cancel_scanner_audit`,
`generate_collaborator_payload`, and `get_collaborator_interactions`, for 26 total. Individual WebSocket and Scanner
issue reads now require `projectId`; v3 aliases are not advertised.

The unified send tool always disables redirects, bounds its timeout and response preview, and reports ambiguous
post-delivery failures as `execution_uncertain`. Unified routing preserves destination-specific approval and audit
classification; HTTP/2-to-Intruder is rejected until verified against a supported Burp runtime. Safe-regex HTTP and
WebSocket searches use 10,000-record/32 MiB budgets and conservative regex validation. HTTP regex search deliberately
bypasses metadata-index hints.

### v4.1 structured results

Version 4.1 keeps the 26/19 tool names and inputs stable while completing output-schema coverage. Every advertised tool
now returns MCP `structuredContent`. The seven previously text-only configuration, global-control, active-editor,
transform, and random-data tools preserve their bounded legacy text block for clients that still consume it, and add:

- a machine-readable `status` code;
- explicit `retry` guidance such as `after_correction`, `after_user_action`, or `do_not_retry`;
- typed bounded output fields instead of requiring clients to parse JSON embedded in text; and
- `executionState` on mutations, where `uncertain` means the side effect may already exist and must not be retried
  automatically.

Expected validation, approval, disabled-feature, availability, output-limit, and Burp errors are represented in the
structured result. Correction-required validation, output-limit, and Burp failures also set MCP `isError=true`; ordinary
approval, disabled, and unavailable outcomes remain non-protocol structured outcomes. Malformed MCP arguments that
cannot be deserialized still use the protocol-level tool error path.

### v4.3 session-scoped approvals

Version 4.3 keeps the 26/19 tool catalog and all tool inputs stable while adding a safer alternative to persistent
approval bypasses. Outbound HTTP, request routing, Target scope changes, and each project-data source can be approved
for only the current MCP session. Outbound HTTP uses the explicit **Allow All for This Session** label because that grant
covers every syntactically valid destination in that session; target validation and all other tool safeguards remain
active. Project-data grants remain source-specific (for example, Site Map does not grant HTTP history access).

Session approval state is a fixed enum set attached to the bounded 32-session registry. It stores no URL, target,
header, body, project identifier, or client-provided value and is removed on authenticated `DELETE /mcp`, idle expiry,
capacity eviction, a project transition detected at request admission, listener restart, or Burp shutdown. A project
transition also closes the old MCP sessions before a newly initialized session can use the current project. **Reset
active session approvals** clears all current grants without cancelling operations that have already started. **Reset all
persistent approvals...** restores outbound HTTP, routing, Scope, and project-data policies to prompt-by-default and
removes saved HTTP approval targets.

### v4.4 native resources and prompts

Version 4.4 keeps the Professional/Community tool catalogs at 26/19 and adds the MCP `resources` and `prompts`
capabilities. Community advertises 3 fixed resources, 4 resource templates, and 3 prompts; Professional advertises the
same 3 fixed resources plus 7 templates and 4 prompts. The fixed JSON resources are:

- `burp://diagnostics` — secret-free aggregate listener, session, liveness, and approval counters;
- `burp://project/summary` — the current opaque project ID, with local project names and paths omitted; and
- `burp://scope/summary` — project binding and MCP scope policy, explicitly noting that Montoya cannot enumerate
  configured scope rules.

Parameterized resources use project-scoped stable IDs returned by the existing searches:

```text
burp://http/{projectId}/{source}/{id}
burp://http/{projectId}/{source}/{id}/{part}
burp://websocket/{projectId}/{id}
burp://websocket/{projectId}/{id}/{variant}
burp://scanner-issue/{projectId}/{id}
burp://scanner-issue/{projectId}/{id}/{field}
burp://scanner-issue/{projectId}/{id}/{field}/{evidenceIndex}
```

HTTP, WebSocket, and Scanner resources reuse the existing source approval checks on every read, including memory-only
session grants, and revalidate the current project and stable ID before returning bounded content. Message and evidence
resources return the first 32 KiB slice by default; use the corresponding detail tool when further byte pagination is
required. URIs must be canonical. Resource subscriptions and list-change notifications remain unadvertised because the
catalog is fixed for a listener lifetime and Kotlin SDK `0.14.0` does not expose bounded, project-aware subscription
admission or selective invalidation. See [PROJECT_BOUND_NOTIFICATIONS.md](docs/PROJECT_BOUND_NOTIFICATIONS.md).

Reusable prompts are `analyze_http_without_sending`, `compare_http_references`, and
`review_auth_session_handling`; Professional also provides `summarize_scanner_issue`. Prompt arguments are bounded,
prompts do not read project data themselves, and each workflow explicitly prohibits hidden request sending, routing,
or mutation. Both native Streamable HTTP clients and the embedded stdio proxy preserve these protocol features.

Starting with v4.4.1, right-click exactly one Proxy history, Site Map, Organizer, WebSocket history, or Professional
Scanner issue item and choose **Copy MCP reference**. The official Montoya context-menu provider copies only the
canonical project-scoped `burp://` reference; it does not copy raw traffic, an endpoint, a bearer token, or a local
path. Potentially expensive fallback source matching and Scanner issue hashing run on a bounded background worker
rather than Burp's event dispatch thread, and project transitions or ambiguous matches fail closed. Resource URIs remain
scoped by the MCP server connection, so users with multiple Burp servers should use the reference with the originating
configured server. No instance identifier was added to the stable v4 URI templates.

### Bounded operation progress and cancellation

`search_http_messages`, `summarize_http_attack_surface`, and `search_websocket_messages` emit six monotonic fixed-stage
progress notifications when the caller supplies an MCP progress token. Stage messages describe only validation,
approval, bounded snapshot preparation, scanning or aggregation, final verification, and completion; they contain no
project ID, filter, target, traffic, or credential value. Retries caused by an internal snapshot revalidation do not
regress or multiply progress stages.

The bounded scan and metadata-refresh loops cooperatively check coroutine cancellation between small record batches.
Cancellation propagates without returning a misleading partial success. Kotlin SDK `0.14.0` does not yet connect an
incoming `notifications/cancelled` message to the active server handler, so v4 does not claim that wire-level path.
A client must also keep the optional `GET /mcp` stream connected to receive progress; a POST-only client still receives
the same final structured result. Scan/content limits and continuation cursors remain the explicit non-cancellation
partial-completion mechanism.

State-changing HTTP, Scope, Scanner, configuration, control, and editor tools preserve their existing result schemas:
execution is not-started, completed, or uncertain. Every uncertain result carries bounded redacted guidance not to retry
automatically and to reconcile Burp state first; this includes a timeout reported by Burp's synchronous execution API
after dispatch or a partial multi-target mutation. Coroutine cancellation is propagated instead of being reformatted as a result. Scanner target submission also
checks cancellation between bounded targets and attempts to delete a task whose ID was not returned to the caller.

### v4.2 transport lifecycle and approval controls

Version 4.2 keeps the 26/19 tool catalog and all tool inputs stable. The embedded stdio proxy now performs bounded,
best-effort session termination on graceful EOF, while the server exposes value-free event-stream, liveness, DELETE,
and pressure-eviction diagnostics. Target scope include/exclude reviews also add **Always Allow** backed by a single
local boolean and an MCP-tab control for restoring prompts; no URL, project ID, or client value is persisted. The MCP
tab additionally provides an explicit, unchecked-by-default **Always allow all outbound HTTP requests** control for
users who intentionally want to disable per-target request prompts.

## Build and install

### Install a release

Download [`burp-mcp-all.jar`](https://github.com/sehoon123/mcp-server/releases/latest/download/burp-mcp-all.jar)
and its [`SHA256SUMS`](https://github.com/sehoon123/mcp-server/releases/latest/download/SHA256SUMS) file from the
latest release. Releases also include a CycloneDX SBOM, [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md), the
[`LICENSE`](LICENSE), and the point-in-time [`vulnerability report`](docs/VULNERABILITY_REPORT.md). Install the JAR
through **Extensions → Installed → Add → Java**. Do not install a separate proxy JAR.

On systems with `sha256sum`, verify the download before installation:

```shell
sha256sum -c SHA256SUMS
```

### Build from source

Building requires JDK 21 or newer:

```bash
git clone https://github.com/sehoon123/mcp-server.git
cd mcp-server
./gradlew embedProxyJar generateSbom
```

The resulting extension is:

```text
build/libs/burp-mcp-all.jar
build/reports/compliance/bom.cdx.json
```

When updating the companion proxy, build and record it reproducibly with:

```bash
./scripts/update-proxy.sh ../mcp-proxy
```

`embedProxyJar` verifies the pinned source checksum and the copy inside the completed extension. Proxy and extension
archives use normalized timestamps and stable entry ordering so identical inputs produce byte-identical JARs.
`generateSbom` is a cacheable, configuration-cache-compatible task and verifies the proxy checksum again while creating
the deterministic CycloneDX 1.6 document.

Load the resulting JAR in Burp through **Extensions → Installed → Add → Java**.

## Configure Burp

Open the **MCP** tab in Burp:

- Enable or stop the MCP server and confirm the loaded extension version shown under the MCP heading.
- The settings surface tracks the available Burp viewport width, wraps explanatory text, and stacks action buttons when needed. Styled buttons, links, and the server toggle retain visible keyboard focus and support Enter/Space; Escape safely closes MCP dialogs. Persistent approval choices use warning styling and state that they do not expire automatically.
- Configure its bind host and port; the default endpoint is `http://127.0.0.1:9876/mcp`.
- Only numeric loopback bind hosts `127.0.0.1` and `::1` are accepted. Wildcard, hostname, and remote binds are rejected.
- Copy or rotate the per-installation bearer token under **Advanced Options**.
- Configure approval requirements for outbound HTTP requests, stable-ID request actions, Target scope changes, and access to sensitive Burp data, including Site Map and Collaborator items.
- `Always allow all outbound HTTP requests` is off by default. Enable it only when every destination may permanently bypass per-target **Allow Once / Allow All for This Session / Always Allow Host / Always Allow Host:Port / Deny** review; target syntax validation and all other tool safeguards remain active.
- Request-routing and Target scope dialogs offer **Allow Once / Allow for This Session / Always Allow / Deny**. Project-data dialogs offer the same session lifetime for one data source at a time. Re-enable the corresponding approval checkbox to restore prompts after a persistent Always Allow choice. Configuration, Scanner, editor, and other global-state mutations still require explicit **Allow Once / Deny** approval.
- Use **Reset active session approvals** to revoke future use of all memory-only grants without cancelling already-started operations. Use **Reset all persistent approvals...** to restore every saved HTTP, routing, Scope, and project-data approval bypass to prompt-by-default.
- Enable configuration-editing tools only when they are required.
- Use **Diagnostics and Safety** to inspect listener/session/admission, event-stream/liveness, and session-cleanup counters plus verified embedded-proxy provenance, copy a redacted diagnostic report, and manage the bounded audit trail. If the configured port is occupied, startup reports the numeric local endpoint rather than an internal coroutine-cancellation message.
- Enable **Emergency read-only mode** to block every tool not explicitly annotated read-only. This takes effect immediately for new calls, but it does not cancel Scanner work that Burp has already started.

The production endpoint always requires its bearer token in addition to the loopback restriction. This release does not
support a remote listener; do not weaken the bind or use an unauthenticated forwarding proxy.

### Diagnostics, audit, and emergency read-only mode

The diagnostics view reports only operational metadata: listener state and endpoint, the production protocol target,
active/peak HTTP calls, pending/active sessions, aggregate value-free session-approval counts,
event-stream opens/closes/reopens, liveness ping outcomes, heartbeat failures, explicit session termination,
pressure/idle evictions, request and rejection counters, last activity, a safe last-error summary, and the embedded proxy
version/commit/SHA-256 verification state. Counters reset when the listener starts and
use fixed-cardinality atomic storage, not per-client records. **Copy redacted diagnostics**
never includes the bearer token, message content, header values, client-provided identifiers, or local file paths.

Persistent audit logging is enabled by default and retains 250 records; the UI allows 50–1,000, with a fixed 30-day
maximum age. Records contain the timestamp, a one-way 12-hex session correlation, tool name, read-only classification,
declared argument **field names only**, approval decisions, duration, outcome, and exception type when applicable. They never contain argument values,
request/response bodies, header values, credentials, paths, or raw exception messages. Writes are asynchronously
debounced and stored in Burp extension data with a 1 MiB document cap. **Copy recent redacted audit** exports at most
100 complete JSONL records and 64 KiB of text. Disabling logging preserves existing records; **Clear audit...** deletes
them after confirmation.

Emergency read-only mode is a local safety interlock, not a replacement for Scope, approval, or authentication policy.
Read and comparison tools continue to work and retain their normal data-access approvals. Request sending, routing,
payload generation, Scope/config/editor/global-state changes, Scanner start/cancel, and every other non-read-only tool
are rejected before tool input is executed.

## Unified HTTP search

Use `search_http_messages` to search compact HTTP metadata. It searches Proxy history by default; set `sources` to any
combination of `proxy`, `site_map`, and `organizer` to search those stores in a fixed order. Available filters include
exact host, literal path, literal request/response content, or one conservatively safe content regex, plus methods,
status codes, MIME types, in-scope state, and response presence. Literal text and regex are mutually exclusive. Results
default to newest-first within each source; regex is case-sensitive unless `caseSensitive: false` is explicit.

The default page size is 25 and the maximum is 50. If `hasMore` is true, call the tool again with `cursor` set to the
returned `nextCursor` (and optionally a new `limit`). Cursors are signed, bound to the current Burp project and original
query, and preserve
the source sizes seen by the first page. Appended traffic does not leak into an existing snapshot; cleared or reordered
sources return `stale_cursor` instead of silently skipping or duplicating records. Cursors are intentionally invalidated
when the MCP server restarts.

Each result contains the current Burp `projectId` and a `{source, id}` reference. Pass both unchanged to
`get_http_message`, regardless of whether the source is `proxy`, `organizer`, or `site_map`. Numeric Proxy/Organizer
IDs and opaque Site Map IDs are validated according to the selected source.

Search work is bounded per call to 10,000 metadata records. Literal and safe-regex content searches additionally inspect
at most 32 MiB of message data; individually oversized messages are counted in `oversizedContentSkipped`. URLs, notes, result
counts, cursor sizes, and detail reads are also bounded.

Eligible newest-first Proxy and Organizer searches without a content predicate can reuse recent, already-warm body-free
index entries for host, path, method, status, MIME, scope, and response-presence filtering. Search validates the current
source size and at most 16 anchors per warm source but never performs a cold index build. A cached mismatch only
predicts which field to read: the extension rechecks that field and the numeric Proxy/Organizer ID on the current Burp
record before skipping it, so stale, reordered, query-bearing, or replaced records fall back to the original raw
matcher. Site Map, expired, unindexed, contended, text, regex, and oldest-first ranges use the raw path. The 10,000-record
count, 32 MiB content budget, signed cursor, result order, and selected-record identity behavior are unchanged; query
values are never added to the index.

Use `send_raw_http_request` for new raw traffic. It accepts exactly one HTTP/1.1 or HTTP/2 variant, uses an explicit
Montoya protocol mode, denies redirects, bounds response timeout/body output, and adds completed exchanges to Site Map
on a best-effort basis. Use `route_raw_http_request` for exactly one Repeater, Intruder, or Organizer destination. Both
return structured execution state; `uncertain` means the side effect may exist and must not be retried automatically.
The older protocol- and destination-specific names were removed in v4.

## WebSocket search

Use `search_websocket_messages` with the current `projectId` to search Proxy WebSocket history by connection ID,
direction, listener port, or one conservatively safe payload regex. Pages contain at most 50 compact summaries and scan
at most 10,000 raw records. Regex calls account original and edited variants against a 32 MiB payload budget, skip
individually oversized records, and default to case-sensitive matching.

The signed cursor binds the project, query, order, original source size, raw source index, and source-boundary anchors.
Appended messages are excluded from an existing snapshot; a shrunken or boundary-reordered history returns
`stale_cursor`. Continue with only `projectId`, `cursor` set to the returned `nextCursor`, and optional `limit`. Cursors
are invalidated when the MCP server restarts. Use the returned numeric ID and the same required `projectId` with
`get_websocket_message_by_id` for a bounded original or edited payload slice.

## Body-free attack-surface summary

Use `summarize_http_attack_surface` with the current `projectId` to aggregate services, methods, status classes, MIME
types, file extensions, response presence, and normalized path prefixes without returning complete messages. It defaults
to the newest bounded Proxy metadata currently classified as in scope. Select `site_map` or `organizer` explicitly when those approved
stores are needed; `pathDepth`, `serviceLimit`, and `pathLimit` are bounded.

The extension-lifetime index keeps at most 5,000 newest records per selected source. Every result reports the source's
total size, indexed range, unavailable and omitted records, output truncation, and whether the cache was reused,
incrementally updated, or rebuilt. Query strings are discarded, likely numeric/UUID/token path segments are normalized,
and retained records contain no body, header or note values, complete URL, or Montoya object. A project-ID change drops
all old entries before another summary can be returned. Bounded metadata anchors are checked on reuse, entries are
rebuilt after at most 30 seconds, and Scope/project-option mutations performed through MCP invalidate the cache.

Counts represent records in each selected source; the same exchange appearing in multiple stores is not deduplicated.
This aggregate is a discovery view, not an action authority. Continue to use the stable-reference tools for details or
mutations; they resolve the current Burp record and verify its project/identity immediately before use.

## Stable-ID request actions

Copy `projectId` and the complete `{source, id}` reference from `search_http_messages`; do not reconstruct the original
HTTP message in the model. Two structured tools resolve the current Burp item and fail closed if its project or opaque
Site Map identity no longer matches:

- `send_http_request_from_id` replays one request to its original network destination.
- `route_http_message_from_id` routes one request to exactly one `repeater`, `intruder`, or `organizer` destination.

An optional `patch` can change the method or path; remove, set, or add headers; remove, set, or add typed URL/body/cookie/
XML/multipart/JSON parameters; or replace the body as UTF-8 text or base64. Body replacement cannot be mixed with
body-backed parameter mutations. The destination service cannot be changed by a patch, so the approved Burp request
remains bound to its original host, port, and TLS mode.

```json
{
  "projectId": "<projectId from search_http_messages>",
  "ref": {"source": "proxy", "id": "42"},
  "patch": {
    "method": "POST",
    "setHeaders": [{"name": "Content-Type", "value": "application/json"}],
    "body": {"encoding": "text", "data": "{\"enabled\":true}"}
  }
}
```

Source and resulting requests are capped at 2 MiB; replacement bodies at 1 MiB; header and parameter mutations at 64
each. `route_http_message_from_id` with `destination: "intruder"` can additionally resolve up to 32 semantic parameter,
header-value, or whole-body insertion points; clients cannot supply raw byte offsets. `tabName` is accepted only for
Repeater or Intruder, and `insertionPoints` only for Intruder. HTTP replay defaults to the source protocol, rejects every
automatic redirect mode because redirected destinations cannot be reviewed separately, uses a 30-second response timeout,
and returns at most an 8 KiB body preview by default
(64 KiB maximum). Responses are recorded in Site Map on a best-effort basis. When the recorded item can be located,
`recordedRef` contains the exact opaque Site Map reference for follow-up reads or focused audits. Unmodified Organizer
actions preserve a source response when the Montoya source supports it; patched requests never attach a now-mismatched
response.

Each action returns structured `status` and `executionState`. `not_started` is safe with respect to that invocation.
`uncertain` means a Burp API call may already have completed and **must not be retried automatically**. Routing actions
show the exact resulting request and a normalized change summary when request-action approval is enabled. The dialog
provides **Allow Once**, **Allow for This Session**, **Always Allow**, and **Deny**. The session choice retains no
request or target value and expires with that MCP session. Always Allow intentionally disables all future routing-action
prompts until `Require approval for request routing actions` is re-enabled in the MCP tab. Audit
lines contain only source/reference, target, byte count, patch flag, destination, and outcome; request bodies and header
values are not logged.

## Scope, comparison, and focused Scanner audits

Use `check_scope` for a bounded read of up to 32 explicit URLs or stable HTTP references. `update_scope` combines include
and exclude operations through `operation: "include" | "exclude"`; it normalizes every URL and validates the project
and all references first. Its review offers **Allow Once**, **Allow for This Session**, **Always Allow**, and **Deny**.
The session choice covers later include/exclude reviews only for that MCP session and stores no URL or project value.
Always Allow applies only to future Target scope include/exclude prompts and persists no URL or project value; restore prompts with `Require approval
for Target scope changes` in the MCP tab. Validation, project rechecks, mutation serialization, post-change verification,
and uncertain-result handling remain active even when prompts are disabled. Scope mutation is verified after each URL.
`executionState: "uncertain"` means a partial change may exist and must not be retried automatically.

`compare_http_messages` compares 2–8 Proxy, Site Map, or Organizer references. It returns bounded inspected-byte hashes,
header invariants/variants, a first-difference excerpt for two messages, and optional Burp response-variation attributes.
The default per-message inspection limit is 256 KiB and the maximum is 1 MiB. `allEqual: null` means the inspected
prefixes matched but truncation prevents a complete equality claim.

Burp Professional additionally exposes:

- `start_scanner_audit_from_ids`
- `get_scanner_audit`
- `cancel_scanner_audit`

These tools do not crawl. Every target must already be in Burp Target scope. Passive mode accepts only messages with a
response and sends no target traffic. Active mode accepts at most four targets and requires explicit semantic insertion
points for every target; no implicit whole-request audit is permitted. Starting and cancelling always require explicit
Burp approval. Task IDs are random, project-bound, retained only by this extension instance, and status/cancellation
cannot address unrelated Burp tasks. Some Burp runtimes do not expose issue objects while an audit is live; in that
case status and counters still return `status: "ok"` with `issuesUnavailable: true` and a bounded warning. If start or
cancellation returns `actionState: "uncertain"`, do not retry it automatically; reconcile the returned task ID and Burp
Scanner UI first.

## Collaborator polling

On Burp Professional, `generate_collaborator_payload` requires the current `projectId` and returns both a payload and
its interaction ID; optional `customData` follows Burp's 1–16 ASCII-alphanumeric limit. Pass the same `projectId` and that ID as
`payloadId` to `get_collaborator_interactions`. The read tool supports an ISO-8601 `since` filter, Burp's
interaction-ID filter, `waitSeconds` from 0 to 120, up to 50 results, newest/oldest ordering, and text or base64 detail
slices. At most four waits run concurrently. Polling emits MCP progress when the client supplies a progress token and
propagates cancellation; returned metadata, per-field details, total detail bytes, and scanned interactions are bounded.
Collaborator interaction reads use their own **Always allow** data-access option in the MCP tab.

## Stable history access

HTTP discovery uses `search_http_messages`; WebSocket discovery uses `search_websocket_messages`. Both return at most 50
compact complete summaries, enforce 10,000-record and 32 MiB content-search budgets, and use signed raw-source-index
cursors instead of offset-based compatibility lists. Their optional regex accepts at most 512 characters and
conservatively rejects backreferences, lookarounds, quantified groups, and multiple unbounded quantifiers. Summaries
expose project-scoped references; Scanner issue IDs are deterministic `issue_<hash>` values derived from issue identity
fields.

Use the corresponding read tool to fetch only the required record and field:

- `get_http_message` for Proxy, Site Map, or Organizer `{source, id}` references
- `get_websocket_message_by_id`
- `get_scanner_issue_by_id` (Burp Professional)

HTTP, Site Map, and Organizer reads support `metadata`, complete request/response messages, headers, or bodies. Scanner reads
support metadata, detail, remediation, and individual evidence request/response messages. Content reads use byte
offsets, default to 32 KiB, and are capped at 256 KiB per call. Responses include `totalBytes`, `hasMore`, and
`nextOffsetBytes`; repeat the call with the next offset to retrieve the complete field. Use `encoding: "base64"` for
byte-exact binary content.

WebSocket and Scanner issue detail calls require the current `projectId`, include it in results, and recheck it after
source lookup and bounded content materialization.

These read tools return both JSON text and MCP `structuredContent`, advertise output schemas, and carry read-only,
non-destructive, idempotent tool annotations. Sensitive data approval is evaluated on every read. On Professional,
`get_scanner_issues` keeps legacy offset/count calls compatible with a 512 KiB text safety cap; set `cursorMode: true`
or supply severity, confidence,
exact-host, or name filters to use compact
newest/oldest pagination. Cursor mode returns at most 50 summaries, scans at most 10,000 issues per call, and uses a
signed project/query/snapshot cursor that is invalidated on MCP server restart.

## Configure clients

### Before connecting

1. Install only `burp-mcp-all.jar` as a Java extension in Burp.
2. Open Burp's **MCP** tab and make sure **Enabled** is on.
3. Under **Advanced Options**, copy the local bearer token and configure the client as shown below.
4. Keep Burp running while the MCP client is in use.

Native Streamable HTTP clients connect directly to:

```text
http://127.0.0.1:9876/mcp
```

The `/mcp` suffix is required. Every production request must include:

```http
Authorization: Bearer <token copied from Burp Advanced Options>
```

The endpoint accepts only numeric loopback binds and has no TLS because traffic never leaves the local host. Bearer
authentication is still mandatory and browser `Origin`/`Host` checks are defense in depth, not an authentication
replacement. Ordinary calls return JSON; the same endpoint can optionally use an event stream for server-initiated
requests. Never commit the token to a repository.

The following examples are alternatives. Configure only the clients you actually use.

### Claude Code

Claude Code supports Streamable HTTP directly, so it does not need the embedded stdio proxy.

Add Burp for the current user:

```shell
export BURP_MCP_BEARER_TOKEN='<token copied from Burp>'
claude mcp add --transport http burp --scope user \
  --header "Authorization: Bearer $BURP_MCP_BEARER_TOKEN" \
  http://127.0.0.1:9876/mcp
claude mcp list
```

For a project-shared configuration, use `--scope project`. Claude creates `.mcp.json`; the equivalent file is:

```json
{
  "mcpServers": {
    "burp": {
      "type": "http",
      "url": "http://127.0.0.1:9876/mcp",
      "headers": {
        "Authorization": "Bearer ${BURP_MCP_BEARER_TOKEN}"
      }
    }
  }
}
```

Claude Code expands `BURP_MCP_BEARER_TOKEN` from its environment. Claude Code requires `"type": "http"` (or its `"streamable-http"` alias) when an entry uses `url`. After opening a
project containing `.mcp.json`, review and approve the server when Claude asks whether to trust it.

### Claude Desktop and other stdio-only clients

Use **Install to Claude Desktop** in Burp's MCP tab. The installer extracts the proxy already packaged inside
`burp-mcp-all.jar` and adds a `burp` entry to Claude Desktop's configuration. You do **not** need to download,
install, or update `mcp-proxy-all.jar` separately.

The generated configuration is equivalent to:

```json
{
  "mcpServers": {
    "burp": {
      "command": "<path to the Java executable used by Burp>",
      "args": [
        "-jar",
        "<path to the automatically extracted mcp-proxy-all.jar>",
        "--mcp-url",
        "http://127.0.0.1:9876/mcp",
        "--bearer-token-env",
        "BURP_MCP_BEARER_TOKEN"
      ],
      "env": {
        "BURP_MCP_BEARER_TOKEN": "<token installed by Burp>"
      }
    }
  }
}
```

A typical Windows installation resolves those placeholders to paths like:

```json
{
  "mcpServers": {
    "burp": {
      "command": "C:\\Users\\<user>\\AppData\\Local\\BurpSuite\\jre\\bin\\java.exe",
      "args": [
        "-jar",
        "C:\\Users\\<user>\\AppData\\Roaming\\BurpSuite\\mcp-proxy\\mcp-proxy-all.jar",
        "--mcp-url",
        "http://127.0.0.1:9876/mcp",
        "--bearer-token-env",
        "BURP_MCP_BEARER_TOKEN"
      ],
      "env": {
        "BURP_MCP_BEARER_TOKEN": "<token installed by Burp>"
      }
    }
  }
}
```

The actual Burp installation path can differ, so prefer the installer-generated values. The installer validates the
packaged proxy checksum, backs up the existing client configuration as `*.burp-mcp.bak`, and replaces configuration and
proxy files atomically with owner-only POSIX permissions where supported. Claude Desktop requires its environment value
in local configuration, so that file and its backup contain the token in plaintext; do not share either file. Restart
Claude Desktop after installation. Previously generated `--sse-url http://127.0.0.1:9876` entries remain accepted as
migration aliases, but the proxy still uses authenticated Streamable HTTP at `/mcp`. Graceful stdio EOF and normal
proxy process shutdown send authenticated `DELETE /mcp`; ambiguous in-flight call failures do not terminate work that
Burp may still be executing.

### mcporter

Register the native HTTP endpoint in the user-level mcporter configuration:

```shell
export BURP_MCP_BEARER_TOKEN='<token copied from Burp>'
mcporter config add burp http://127.0.0.1:9876/mcp --scope home \
  --header 'Authorization=Bearer ${BURP_MCP_BEARER_TOKEN}'
# Set the resulting burp entry's lifecycle to "keep-alive" as shown below.
mcporter list burp --schema
```

For a repository-local configuration, use `--scope project`. The equivalent `config/mcporter.json` is:

```json
{
  "mcpServers": {
    "burp": {
      "url": "http://127.0.0.1:9876/mcp",
      "lifecycle": "keep-alive",
      "headers": {
        "Authorization": "Bearer ${BURP_MCP_BEARER_TOKEN}"
      }
    }
  }
}
```

The environment placeholder avoids persisting the token, but still restrict permissions on `mcporter.json`. The
`keep-alive` daemon reuses one Streamable HTTP session across separate CLI invocations. Without it, current mcporter
versions close each ephemeral client without sending the optional HTTP `DELETE`, which can otherwise retain one server
session per command until cleanup. Example tool call:

```shell
mcporter call burp.search_http_messages \
  --args '{"sources":["proxy"],"newestFirst":true,"limit":5}' \
  --output json
```

Burp may show a project-data or action approval dialog depending on the tool and MCP-tab policy.

### Visual Studio Code / GitHub Copilot

Create `.vscode/mcp.json` for a workspace configuration, or run **MCP: Open User Configuration** from the Command
Palette for a user-level configuration:

```json
{
  "inputs": [
    {
      "type": "promptString",
      "id": "burp-mcp-token",
      "description": "Burp MCP local bearer token",
      "password": true
    }
  ],
  "servers": {
    "burp": {
      "type": "http",
      "url": "http://127.0.0.1:9876/mcp",
      "headers": {
        "Authorization": "Bearer ${input:burp-mcp-token}"
      }
    }
  }
}
```

Use the MCP server controls in VS Code to start or reconnect the entry after Burp is running.

### Cursor

Create `.cursor/mcp.json` in a project, or `~/.cursor/mcp.json` for a global configuration:

```json
{
  "mcpServers": {
    "burp": {
      "url": "http://127.0.0.1:9876/mcp",
      "headers": {
        "Authorization": "Bearer ${env:BURP_MCP_BEARER_TOKEN}"
      }
    }
  }
}
```

Set `BURP_MCP_BEARER_TOKEN` in the environment that launches Cursor. Cursor recognizes this URL as a Streamable HTTP server.

### OpenAI Codex

Codex CLI and the Codex IDE extension share `~/.codex/config.toml`. Trusted projects can instead use
`.codex/config.toml`:

```toml
[mcp_servers.burp]
url = "http://127.0.0.1:9876/mcp"
bearer_token_env_var = "BURP_MCP_BEARER_TOKEN"
enabled = true
```

Set `BURP_MCP_BEARER_TOKEN` in the environment that launches Codex, then restart or reconnect Codex.

### Rotate or replace the token

1. Stop using MCP clients, then choose **Rotate local bearer token...** under Burp **MCP → Advanced Options**.
2. Stop and start the Burp MCP server so the listener begins requiring the new token.
3. Run **Install to Claude Desktop** again for the stdio configuration. For native clients, replace the environment,
   secret input, or header value shown above.
4. Restart or reconnect every client. Delete obsolete installer backups after confirming the new configuration works.

Rotation immediately invalidates the persisted credential, but an already-running listener retains its startup token
until restarted. A `401 Unauthorized` after rotation almost always means one side still has the old value.

### Connection troubleshooting

- A `401` means the bearer header is missing, malformed, or stale. Copy the current token, restart the Burp listener,
  and update or reinstall the client.
- A `404` usually means the client was pointed at `/` or an obsolete SSE path; use `/mcp`. The root path intentionally
  does not redirect because authorization headers must not be moved implicitly.
- A hand-written Streamable HTTP POST must advertise `Accept: application/json, text/event-stream`; initialize with a
  supported protocol version rather than the legacy `2024-11-05` version.
- `Server not initialized` from a hand-written HTTP request means the endpoint is reachable but the request did not
  perform the MCP initialization handshake.
- `MCP session capacity is full` usually means a client repeatedly initialized sessions without terminating or reusing
  them. For mcporter, use `"lifecycle": "keep-alive"`; native clients should send `DELETE /mcp` during graceful
  shutdown. The server also reclaims the least-recently-used inactive session whose optional Streamable HTTP event
  stream has disconnected when capacity is under pressure; active calls and open streams are never displaced.
- Keep only one copy of the Burp MCP extension enabled to avoid a port conflict on `9876`.
- Native HTTP clients do not use `mcp-proxy-all.jar`; stdio-only clients use the copy extracted by the extension.
- `127.0.0.1` refers to the client's own host. A client inside a container or separate VM cannot reach Burp through
  that address; do not weaken the loopback binding without adding an authenticated remote-access design.

Client references: [Claude Code](https://code.claude.com/docs/en/mcp),
[VS Code](https://code.visualstudio.com/docs/agent-customization/mcp-servers),
[Cursor](https://cursor.com/docs/context/mcp), and
[Codex](https://developers.openai.com/codex/mcp/).

The embedded proxy source is maintained in the companion fork:
[sehoon123/mcp-proxy](https://github.com/sehoon123/mcp-proxy).

## Developing tools

Tools are defined in `src/main/kotlin/net/portswigger/mcp/tools/Tools.kt`. Parameters use serializable data classes;
tool names and JSON schemas are derived from those types. Implement `Paginated` for potentially large result sets.

CI also runs the official MCP conformance scenarios for initialization, ping, tool discovery, DNS-rebinding
protection, and multiple Streamable HTTP SSE streams. Integration tests negotiate `2025-03-26`, `2025-06-18`, and
`2025-11-25`; the modern per-request scenario has a stale-sensitive expected-failure baseline until the protocol and
pinned production SDK support that lifecycle.

See [docs/PERFORMANCE.md](docs/PERFORMANCE.md) for runtime analysis, [docs/ROADMAP.md](docs/ROADMAP.md) for proposed
improvements, [docs/V5_READINESS.md](docs/V5_READINESS.md) for the modern-protocol release gates, and
[docs/V5_APPROVAL_MODEL.md](docs/V5_APPROVAL_MODEL.md) for the fail-safe sessionless approval baseline.
