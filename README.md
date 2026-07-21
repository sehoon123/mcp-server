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
- Proxy and WebSocket history search with pagination
- Repeater, Intruder, Organizer, Scanner, and Collaborator integrations
- Project and user configuration tools with credential filtering
- URL/Base64 utilities and random data generation
- Browser-client CORS support and SDK DNS-rebinding protection

## Build and install

### Requirements

- JDK 21 or newer
- The `jar` command available on `PATH`

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

`embedProxyJar` verifies the SHA-256 recorded in `libs/mcp-proxy-source.txt` before packaging.

Load the final JAR in Burp through **Extensions → Installed → Add → Java**.

## Configure Burp

Open the **MCP** tab in Burp:

- Enable or stop the MCP server.
- Configure its bind host and port; the default endpoint is `http://127.0.0.1:9876/mcp`.
- Configure approval requirements for outbound HTTP requests and access to sensitive Burp data.
- Enable configuration-editing tools only when they are required.

The default loopback binding is recommended. Do not expose the endpoint to another network until authentication and
TLS are configured in front of it.

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

See [docs/ROADMAP.md](docs/ROADMAP.md) for proposed security, protocol, and tool improvements.
