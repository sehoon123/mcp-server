# Burp Suite MCP Server Extension

Integrate Burp Suite with AI clients through the Model Context Protocol (MCP).

This fork of [PortSwigger/mcp-server](https://github.com/PortSwigger/mcp-server) uses the modern **Streamable HTTP**
transport exclusively. The deprecated two-endpoint HTTP+SSE server has been removed.

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

## Features

- Single Streamable HTTP endpoint at `/mcp`
- Automatic Claude Desktop configuration through the embedded stdio proxy
- Compact catalog: 31 tools on Professional and 24 on Community, grouped by common safety policy
- HTTP/1.1 and HTTP/2 request tools with target approval controls
- Unified compact HTTP search across Proxy history, Site Map, and Organizer with signed snapshot cursors
- Body-free, project-bounded HTTP metadata indexing and aggregate attack-surface summaries
- Proxy, WebSocket, Organizer, Site Map, and Scanner summaries with stable IDs and bounded detail reads
- Project-scoped request replay and structured mutation from stable IDs, with Repeater, Intruder, and Organizer routing
- Explicit Target scope checks/updates and bounded HTTP message comparison from stable references
- Focused passive or insertion-point-limited active Scanner audits with extension-owned task status/cancellation (Professional)
- Bounded Collaborator long polling with progress, cancellation, timestamp filtering, and detail slicing (Professional)
- Project and user configuration tools with credential filtering
- Live redacted diagnostics, a bounded persistent audit trail, and an emergency read-only switch
- URL/Base64 utilities and random data generation
- Browser-client CORS support and SDK DNS-rebinding protection

## v3 compact tool catalog

Version 3 consolidates operations only when they share the same MCP safety classification and preserves one side effect
per invocation. This is a breaking tool-name change; removed v2 names are not advertised as aliases because aliases
would defeat the bounded 31-tool catalog.

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

- Enable or stop the MCP server.
- Configure its bind host and port; the default endpoint is `http://127.0.0.1:9876/mcp`.
- Only numeric loopback bind hosts `127.0.0.1` and `::1` are accepted. Wildcard, hostname, and remote binds are rejected.
- Copy or rotate the per-installation bearer token under **Advanced Options**.
- Configure approval requirements for outbound HTTP requests, stable-ID request actions, and access to sensitive Burp data, including Site Map and Collaborator items.
- Enable configuration-editing tools only when they are required. Configuration changes and other global-state mutations still require explicit **Allow Once / Deny** approval.
- Use **Diagnostics and Safety** to inspect listener/session/admission counters and verified embedded-proxy provenance, copy a redacted diagnostic report, and manage the bounded audit trail.
- Enable **Emergency read-only mode** to block every tool not explicitly annotated read-only. This takes effect immediately for new calls, but it does not cancel Scanner work that Burp has already started.

The production endpoint always requires its bearer token in addition to the loopback restriction. This release does not
support a remote listener; do not weaken the bind or use an unauthenticated forwarding proxy.

### Diagnostics, audit, and emergency read-only mode

The diagnostics view reports only operational metadata: listener state and endpoint, the production protocol target,
active/peak HTTP calls, pending/active sessions, request and rejection counters, idle evictions, last activity, a safe
last-error summary, and the embedded proxy version/commit/SHA-256 verification state. **Copy redacted diagnostics**
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
exact host, literal path or request/response content, methods, status codes, MIME types, in-scope state, and response
presence. Results default to newest-first within each source.

The default page size is 25 and the maximum is 50. If `hasMore` is true, call the tool again with only `nextCursor`
(and optionally a new `limit`). Cursors are signed, bound to the current Burp project and original query, and preserve
the source sizes seen by the first page. Appended traffic does not leak into an existing snapshot; cleared or reordered
sources return `stale_cursor` instead of silently skipping or duplicating records. Cursors are intentionally invalidated
when the MCP server restarts.

Each result contains the current Burp `projectId` and a `{source, id}` reference. Pass both unchanged to
`get_http_message`, regardless of whether the source is `proxy`, `organizer`, or `site_map`. Numeric Proxy/Organizer
IDs and opaque Site Map IDs are validated according to the selected source.

Search work is bounded per call to 10,000 metadata records. Literal content searches additionally inspect at most
32 MiB of message data; individually oversized messages are counted in `oversizedContentSkipped`. URLs, notes, result
counts, cursor sizes, and detail reads are also bounded.

Eligible newest-first Proxy and Organizer searches without a content predicate can reuse recent, already-warm body-free
index entries for host, path, method, status, MIME, scope, and response-presence filtering. Search validates the current
source size and at most 16 anchors per warm source but never performs a cold index build. A cached mismatch only
predicts which field to read: the extension rechecks that field and the numeric Proxy/Organizer ID on the current Burp
record before skipping it, so stale, reordered, query-bearing, or replaced records fall back to the original raw
matcher. Site Map, expired, unindexed, contended, text, and oldest-first ranges use the raw path. The 10,000-record
count, 32 MiB content budget, signed cursor, result order, and selected-record identity behavior are unchanged; query
values are never added to the index.

Successful requests issued through `send_http1_request` or `send_http2_request` are added to Burp's Site Map on a
best-effort basis without changing the already-completed request result if local recording fails.

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
provides **Allow Once**, **Always Allow**, and **Deny**. Always Allow intentionally disables all
future routing-action prompts until `Require approval for request routing actions` is re-enabled in the MCP tab. Audit
lines contain only source/reference, target, byte count, patch flag, destination, and outcome; request bodies and header
values are not logged.

## Scope, comparison, and focused Scanner audits

Use `check_scope` for a bounded read of up to 32 explicit URLs or stable HTTP references. `update_scope` combines include
and exclude operations through `operation: "include" | "exclude"`; it normalizes every URL, validates the project and
all references first, and then always opens an **Allow Once / Deny** review. Scope mutation is verified after each URL.
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

The paginated Proxy, WebSocket, and Organizer tools return compact stable-ID summaries by default. Their optional
`regex` field accepts at most 512 characters and conservatively rejects backreferences, lookarounds, quantified groups,
and multiple unbounded quantifiers; omitting it lists the source without regex filtering. Set `summariesOnly=false` only
with one selected `part`, `contentLimit` (8 KiB default, 32 KiB maximum), and `encoding` for a bounded preview. Pages
contain at most 50 records and 128 Ki characters; explicit truncation metadata replaces invalid mid-JSON string cutting.
Summaries expose Burp's project-scoped numeric IDs; Scanner issue IDs are
deterministic `issue_<hash>` values derived from issue identity fields.

Use the corresponding read tool to fetch only the required record and field:

- `get_http_message` for Proxy, Site Map, or Organizer `{source, id}` references
- `get_websocket_message_by_id`
- `get_scanner_issue_by_id` (Burp Professional)

HTTP, Site Map, and Organizer reads support `metadata`, complete request/response messages, headers, or bodies. Scanner reads
support metadata, detail, remediation, and individual evidence request/response messages. Content reads use byte
offsets, default to 32 KiB, and are capped at 256 KiB per call. Responses include `totalBytes`, `hasMore`, and
`nextOffsetBytes`; repeat the call with the next offset to retrieve the complete field. Use `encoding: "base64"` for
byte-exact binary content.

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
migration aliases, but the proxy still uses authenticated Streamable HTTP at `/mcp`.

### mcporter

Register the native HTTP endpoint in the user-level mcporter configuration:

```shell
export BURP_MCP_BEARER_TOKEN='<token copied from Burp>'
mcporter config add burp http://127.0.0.1:9876/mcp --scope home \
  --header "Authorization=Bearer $BURP_MCP_BEARER_TOKEN"
mcporter list burp --schema
```

For a repository-local configuration, use `--scope project`. The equivalent `config/mcporter.json` is:

```json
{
  "mcpServers": {
    "burp": {
      "baseUrl": "http://127.0.0.1:9876/mcp",
      "headers": {
        "Authorization": "Bearer <token copied from Burp>"
      }
    }
  }
}
```

Restrict permissions on `mcporter.json` because this static form contains the token. Example tool call:

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
- A `404` usually means the client was pointed at `/` or an obsolete SSE path; use `/mcp`.
- `Server not initialized` from a hand-written HTTP request means the endpoint is reachable but the request did not
  perform the MCP initialization handshake.
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
`2025-11-25`; the draft SEP-2575 stateless scenario has a stale-sensitive expected-failure baseline until the pinned
production SDK supports that lifecycle.

See [docs/PERFORMANCE.md](docs/PERFORMANCE.md) for the runtime analysis and measurements, and
[docs/ROADMAP.md](docs/ROADMAP.md) for proposed security, protocol, and tool improvements.
