# Burp Suite MCP Server Extension

## Overview

Integrate Burp Suite with AI Clients using the Model Context Protocol (MCP).

This fork of [PortSwigger/mcp-server](https://github.com/PortSwigger/mcp-server) uses Streamable HTTP as the primary
transport while retaining the original SSE endpoint for compatibility.

For more information about the protocol visit: [modelcontextprotocol.io](https://modelcontextprotocol.io/)

## Features

- Connect Burp Suite to AI clients through Streamable HTTP MCP
- Keep legacy SSE compatibility for existing installations
- Automatic installation for Claude Desktop
- Comes with a packaged stdio MCP proxy server

## Usage

- Install the extension in Burp Suite
- Configure your Burp MCP server in the extension settings
- Configure your MCP client to use the Streamable HTTP endpoint (recommended), legacy SSE endpoint, or stdio proxy
- Interact with Burp through your client!

## Installation

### Prerequisites

Ensure that the following prerequisites are met before building and installing the extension:

1. **Java**: Java must be installed and available in your system's PATH. You can verify this by running `java --version` in your terminal.
2. **jar Command**: The `jar` command must be executable and available in your system's PATH. You can verify this by running `jar --version` in your terminal. This is required for building and installing the extension.

### Building the Extension

1. **Clone the Repository**: Obtain the source code for the MCP Server Extension.
   ```
   git clone https://github.com/sehoon123/mcp-server.git
   ```

2. **Navigate to the Project Directory**: Move into the project's root directory.
   ```
   cd mcp-server
   ```

3. **Build the JAR File**: Use Gradle to build the extension.
   ```
   ./gradlew embedProxyJar
   ```

   This command compiles the source code and packages it into a JAR file located in `build/libs/burp-mcp-all.jar`.

### Loading the Extension into Burp Suite

1. **Open Burp Suite**: Launch your Burp Suite application.
2. **Access the Extensions Tab**: Navigate to the `Extensions` tab.
3. **Add the Extension**:
    - Click on `Add`.
    - Set `Extension Type` to `Java`.
    - Click `Select file ...` and choose the JAR file built in the previous step.
    - Click `Next` to load the extension.

Upon successful loading, the MCP Server Extension will be active within Burp Suite.

## Configuration

### Configuring the Extension
Configuration for the extension is done through the Burp Suite UI in the `MCP` tab.
- **Toggle the MCP Server**: The `Enabled` checkbox controls whether the MCP server is active.
- **Enable config editing**: The `Enable tools that can edit your config` checkbox allows the MCP server to expose tools which can edit Burp configuration files.
- **Advanced options**: You can configure the port and host for the MCP server. By default, the Streamable HTTP endpoint is `http://127.0.0.1:9876/mcp`.

### Claude Desktop Client

To fully utilize the MCP Server Extension with Claude, you need to configure your Claude client settings appropriately.
The extension has an installer which will automatically configure the client settings for you.

1. The built-in installer uses a stdio proxy for compatibility with Claude Desktop versions that cannot connect to a
   local Streamable HTTP server directly. The proxy points to the Burp instance running at a known port
   (`localhost:9876`). Clients with Streamable HTTP support should connect directly to `/mcp` instead.

2. **Configure Claude to use the Burp MCP server**  
   You can do this in one of two ways:

    - **Option 1: Run the installer from the extension**
      This will add the Burp MCP server to the Claude Desktop config.

    - **Option 2: Manually edit the config file**  
      Open the file located at `~/Library/Application Support/Claude/claude_desktop_config.json`,
      and replace or update it with the following:
      ```json
      {
        "mcpServers": {
          "burp": {
            "command": "<path to Java executable packaged with Burp>",
            "args": [
                "-jar",
                "/path/to/mcp/proxy/jar/mcp-proxy-all.jar",
                "--sse-url",
                "<your Burp MCP server URL configured in the extension>"
            ]
          }
        }
      }
      ```

3. **Restart Claude Desktop** - assuming Burp is running with the extension loaded.

## Manual installations

### Streamable HTTP MCP Server (recommended)

Configure clients that support Streamable HTTP with the single MCP endpoint:

```
http://127.0.0.1:9876/mcp
```

A typical client entry looks like the following, although the exact configuration keys vary by client:

```json
{
  "mcpServers": {
    "burp": {
      "url": "http://127.0.0.1:9876/mcp"
    }
  }
}
```

Streamable HTTP is the primary transport. Ordinary request/response calls return JSON through one endpoint; optional
server-to-client event streaming remains available through the same endpoint when a client needs it.

### Legacy SSE MCP Server

The original SSE endpoint remains available at the server root for backwards compatibility:

```
http://127.0.0.1:9876
```

New client configurations should use `/mcp` instead.

### Stdio MCP Proxy Server

The source code for the proxy server can be found here: [MCP Proxy Server](https://github.com/PortSwigger/mcp-proxy).
The extension packages this proxy for clients that only support stdio. It forwards stdio requests to the legacy SSE
compatibility endpoint.

Use the extension's installer to extract the proxy JAR, then configure the following command and arguments:

```
/path/to/packaged/burp/java -jar /path/to/proxy/jar/mcp-proxy-all.jar --sse-url http://127.0.0.1:9876
```

### Creating / modifying tools

Tools are defined in `src/main/kotlin/net/portswigger/mcp/tools/Tools.kt`. To define new tools, create a new serializable
data class with the required parameters which will come from the LLM.

The tool name is auto-derived from its parameters data class. A description is also needed for the LLM. You can return
a string (or richer PromptMessageContents) to provide data back to the LLM.

Extend the Paginated interface to add auto-pagination support.
