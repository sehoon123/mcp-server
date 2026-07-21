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
- HTTP/1.1 and HTTP/2 request tools with target approval controls
- Unified compact HTTP search across Proxy history, Site Map, and Organizer with signed snapshot cursors
- Proxy, WebSocket, Organizer, Site Map, and Scanner summaries with stable IDs and bounded detail reads
- Project-scoped request replay and structured mutation from stable IDs, with Repeater, Intruder, and Organizer routing
- Repeater, Intruder, Organizer, Scanner, and Collaborator integrations
- Project and user configuration tools with credential filtering
- URL/Base64 utilities and random data generation
- Browser-client CORS support and SDK DNS-rebinding protection

## Build and install

### Install a release

Download [`burp-mcp-all.jar`](https://github.com/sehoon123/mcp-server/releases/latest/download/burp-mcp-all.jar)
and its [`SHA256SUMS`](https://github.com/sehoon123/mcp-server/releases/latest/download/SHA256SUMS) file from the
latest release. Install the JAR through **Extensions → Installed → Add → Java**. Do not install a separate proxy JAR.

On systems with `sha256sum`, verify the download before installation:

```shell
sha256sum -c SHA256SUMS
```

### Build from source

Building requires JDK 21 or newer:

```bash
git clone https://github.com/sehoon123/mcp-server.git
cd mcp-server
./gradlew embedProxyJar
```

The resulting extension is:

```text
build/libs/burp-mcp-all.jar
```

When updating the companion proxy, build and record it reproducibly with:

```bash
./scripts/update-proxy.sh ../mcp-proxy
```

`embedProxyJar` verifies the pinned source checksum and the copy inside the completed extension. Proxy and extension
archives use normalized timestamps and stable entry ordering so identical inputs produce byte-identical JARs.

Load the resulting JAR in Burp through **Extensions → Installed → Add → Java**.

## Configure Burp

Open the **MCP** tab in Burp:

- Enable or stop the MCP server.
- Configure its bind host and port; the default endpoint is `http://127.0.0.1:9876/mcp`.
- Configure approval requirements for outbound HTTP requests, stable-ID request actions, and access to sensitive Burp data, including Site Map items.
- Enable configuration-editing tools only when they are required.

The default loopback binding is recommended. Do not expose the endpoint to another network until authentication and
TLS are configured in front of it.

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

Each result contains the current Burp `projectId` and a `{source, id}` reference. Use:

- `get_http_message_by_id` with the numeric ID when `source` is `proxy`
- `get_organizer_item_by_id` with the numeric ID when `source` is `organizer`
- `get_sitemap_message_by_id` with both `projectId` and the opaque ID when `source` is `site_map`

Search work is bounded per call to 10,000 metadata records. Literal content searches additionally inspect at most
32 MiB of message data; individually oversized messages are counted in `oversizedContentSkipped`. URLs, notes, result
counts, cursor sizes, and detail reads are also bounded. Successful requests issued through `send_http1_request` or
`send_http2_request` are added to Burp's Site Map on a best-effort basis without changing the already-completed request
result if local recording fails.

## Stable-ID request actions

Copy `projectId` and the complete `{source, id}` reference from `search_http_messages`; do not reconstruct the original
HTTP message in the model. The following structured tools resolve the current Burp item and fail closed if its project
or opaque Site Map identity no longer matches:

- `send_http_request_from_id`
- `create_repeater_tab_from_id`
- `send_to_intruder_from_id`
- `send_to_organizer_from_id`

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
each. HTTP replay defaults to the source protocol, never follows redirects unless requested, uses a 30-second response
timeout, and returns at most an 8 KiB body preview by default (64 KiB maximum). Responses are recorded in Site Map on
a best-effort basis. Unmodified Organizer actions preserve a source response when the Montoya source supports it;
patched requests never attach a now-mismatched response.

Each action returns structured `status` and `executionState`. `not_started` is safe with respect to that invocation.
`uncertain` means a Burp API call may already have completed and **must not be retried automatically**. Routing actions
show the exact resulting request and a normalized change summary when request-action approval is enabled. The dialog
provides **Allow Once**, **Always Allow**, and **Deny**. Always Allow intentionally disables all
future routing-action prompts until `Require approval for request routing actions` is re-enabled in the MCP tab. Audit
lines contain only source/reference, target, byte count, patch flag, destination, and outcome; request bodies and header
values are not logged.

## Stable history access

Set `summariesOnly` to `true` on the existing paginated Proxy, WebSocket, Organizer, or Scanner tools to return compact
metadata instead of complete messages. Summaries expose Burp's project-scoped numeric IDs; Scanner issue IDs are
deterministic `issue_<hash>` values derived from issue identity fields.

Use the corresponding read tool to fetch only the required record and field:

- `get_http_message_by_id`
- `get_websocket_message_by_id`
- `get_organizer_item_by_id`
- `get_scanner_issue_by_id` (Burp Professional)

HTTP, Site Map, and Organizer reads support `metadata`, complete request/response messages, headers, or bodies. Scanner reads
support metadata, detail, remediation, and individual evidence request/response messages. Content reads use byte
offsets, default to 32 KiB, and are capped at 256 KiB per call. Responses include `totalBytes`, `hasMore`, and
`nextOffsetBytes`; repeat the call with the next offset to retrieve the complete field. Use `encoding: "base64"` for
byte-exact binary content.

These read tools return both JSON text and MCP `structuredContent`, advertise output schemas, and carry read-only,
non-destructive, idempotent tool annotations. Sensitive data approval is evaluated on every read.

## Configure clients

### Before connecting

1. Install only `burp-mcp-all.jar` as a Java extension in Burp.
2. Open Burp's **MCP** tab and make sure **Enabled** is on.
3. Keep Burp running while the MCP client is in use.

Native Streamable HTTP clients connect directly to:

```text
http://127.0.0.1:9876/mcp
```

The `/mcp` suffix is required. The endpoint is intentionally loopback-only by default and has no bearer-token or TLS
layer, so do not expose it on a LAN or the internet. Ordinary calls return JSON; the same endpoint can optionally use
an event stream for server-initiated requests.

The following examples are alternatives. Configure only the clients you actually use.

### Claude Code

Claude Code supports Streamable HTTP directly, so it does not need the embedded stdio proxy.

Add Burp for the current user:

```shell
claude mcp add --transport http burp --scope user http://127.0.0.1:9876/mcp
claude mcp list
```

For a project-shared configuration, use `--scope project`. Claude creates `.mcp.json`; the equivalent file is:

```json
{
  "mcpServers": {
    "burp": {
      "type": "http",
      "url": "http://127.0.0.1:9876/mcp"
    }
  }
}
```

Claude Code requires `"type": "http"` (or its `"streamable-http"` alias) when an entry uses `url`. After opening a
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
        "http://127.0.0.1:9876/mcp"
      ]
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
        "http://127.0.0.1:9876/mcp"
      ]
    }
  }
}
```

The actual Burp installation path can differ, so prefer the installer-generated values. Restart Claude Desktop after
installation. Previously generated `--sse-url http://127.0.0.1:9876` entries remain accepted as migration aliases, but
the proxy still uses Streamable HTTP at `/mcp`.

### mcporter

Register the native HTTP endpoint in the user-level mcporter configuration:

```shell
mcporter config add burp http://127.0.0.1:9876/mcp --scope home
mcporter list burp --schema
```

For a repository-local configuration, use `--scope project`. The equivalent `config/mcporter.json` is:

```json
{
  "mcpServers": {
    "burp": {
      "baseUrl": "http://127.0.0.1:9876/mcp"
    }
  }
}
```

Example tool call:

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
  "servers": {
    "burp": {
      "type": "http",
      "url": "http://127.0.0.1:9876/mcp"
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
      "url": "http://127.0.0.1:9876/mcp"
    }
  }
}
```

Cursor recognizes this URL as a Streamable HTTP server.

### OpenAI Codex

Codex CLI and the Codex IDE extension share `~/.codex/config.toml`. Trusted projects can instead use
`.codex/config.toml`:

```toml
[mcp_servers.burp]
url = "http://127.0.0.1:9876/mcp"
enabled = true
```

Restart or reconnect Codex after saving the file.

### Connection troubleshooting

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
protection, and concurrent Streamable HTTP POST requests.

See [docs/PERFORMANCE.md](docs/PERFORMANCE.md) for the runtime analysis and measurements, and
[docs/ROADMAP.md](docs/ROADMAP.md) for proposed security, protocol, and tool improvements.
