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
- Repeater, Intruder, Organizer, Scanner, and Collaborator integrations
- Project and user configuration tools with credential filtering
- URL/Base64 utilities and random data generation
- Browser-client CORS support and SDK DNS-rebinding protection

## Build and install

### Requirements

- JDK 21 or newer

### Build

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

Load the final JAR in Burp through **Extensions → Installed → Add → Java**.

## Configure Burp

Open the **MCP** tab in Burp:

- Enable or stop the MCP server.
- Configure its bind host and port; the default endpoint is `http://127.0.0.1:9876/mcp`.
- Configure approval requirements for outbound HTTP requests and access to sensitive Burp data, including Site Map items.
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

### Native Streamable HTTP clients

Point the client directly at:

```text
http://127.0.0.1:9876/mcp
```

A typical configuration is:

```json
{
  "mcpServers": {
    "burp": {
      "url": "http://127.0.0.1:9876/mcp"
    }
  }
}
```

Ordinary request/response calls return JSON. Streamable HTTP can use an optional event stream through the same
endpoint for server-initiated requests.

### Claude Desktop and other stdio-only clients

Use the installer in Burp's MCP tab. It extracts the proxy already packaged inside `burp-mcp-all.jar` and writes a
configuration equivalent to:

```json
{
  "mcpServers": {
    "burp": {
      "command": "<path to the Java executable packaged with Burp>",
      "args": [
        "-jar",
        "/path/to/extracted/mcp-proxy-all.jar",
        "--mcp-url",
        "http://127.0.0.1:9876/mcp"
      ]
    }
  }
}
```

Previously generated configurations using `--sse-url http://127.0.0.1:9876` continue to work: proxy 2.x treats that
option only as a migration alias and connects to `/mcp` with Streamable HTTP.

The proxy source is maintained in the companion fork:
[sehoon123/mcp-proxy](https://github.com/sehoon123/mcp-proxy).

## Developing tools

Tools are defined in `src/main/kotlin/net/portswigger/mcp/tools/Tools.kt`. Parameters use serializable data classes;
tool names and JSON schemas are derived from those types. Implement `Paginated` for potentially large result sets.

CI also runs the official MCP conformance scenarios for initialization, ping, tool discovery, DNS-rebinding
protection, and concurrent Streamable HTTP POST requests.

See [docs/PERFORMANCE.md](docs/PERFORMANCE.md) for the runtime analysis and measurements, and
[docs/ROADMAP.md](docs/ROADMAP.md) for proposed security, protocol, and tool improvements.
