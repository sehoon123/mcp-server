# Migrating to Independent MCP Bridge v4.8

Version 4.8 establishes a new identity for this unofficial independent fork. It does not replace or modify any official
PortSwigger extension installation.

## Identity changes

| Surface | Previous value | v4.8 value |
|---|---|---|
| Product name | MCP Server / Burp MCP Server | Independent MCP Bridge |
| BApp UUID | `9952290f04ed4f628e624d0aa9dccebc` | `c0a454c4079c4cecb627d928a92f9555` |
| Burp suite tab | MCP | MCP Bridge |
| MCP server name | `burp-suite` | `independent-mcp-bridge` |
| Claude Desktop entry | `burp` | `burp-independent` |
| Bearer-token environment variable | `BURP_MCP_BEARER_TOKEN` | `INDEPENDENT_MCP_BRIDGE_BEARER_TOKEN` |
| Extracted stdio proxy | shared `mcp-proxy/` path | isolated `independent-mcp-bridge/proxy/` path |
| Distributor | PortSwigger metadata | `sehoon123` |

The Kotlin package namespace remains `net.portswigger.mcp` for compatibility. It is not distributor branding.

## Upgrade steps

1. Back up Burp and MCP client configuration.
2. Disable or remove the prior `MCP Server` extension before loading Independent MCP Bridge. The new UUID allows both
   to appear side by side, but running both on the default port creates a listener conflict and makes client routing
   ambiguous.
3. Install the v4.8 JAR and confirm that Burp displays **Independent MCP Bridge** and the **MCP Bridge** tab. Because
   the new UUID has separate extension storage, recreate the listener address/port, target allowlist, approval policies,
   audit settings, and other preferences after reviewing their secure defaults. The local bearer token is newly
   generated and the prior token does not authenticate this extension.
4. Re-run the Claude Desktop installer or regenerate manual client configuration. The installer writes the new
   `burp-independent` key and deliberately leaves an existing `burp` key untouched.
5. Remove the old client entry only after the new endpoint completes initialization and a read-only test call. The
   independent installer and proxy extraction path do not rewrite the old `burp` entry or its legacy proxy binary.
6. Review security prompts again. Request-routing approval and outbound-target approval are separate grants in v4.8.

## Compatibility changes

- Scanner IDs and signed cursors produced by older releases may be invalid; obtain fresh references.
- Explicit JSON `null` is validated more precisely in nullable exactly-one schemas.
- Malformed HTTP/2 pseudo-headers and regular headers are rejected before approval or transmission.
- An operation that may have performed a side effect before cancellation or project transition reports
  `execution_uncertain` and must not be retried automatically.
- Direct raw sends do not automatically add a response to Site Map because the current Montoya API cannot bind that
  write atomically to the originating project.

This migration does not move or replace the immutable `v4.7.0` tag or its assets.
