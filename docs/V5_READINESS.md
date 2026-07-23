# v5 protocol readiness

**Status date:** 2026-07-24

Version 5 is reserved for the first production release that adopts the modern, per-request MCP protocol era. The current
production release remains on stable protocol `2025-11-25`. A draft or an SDK branch is not sufficient authority for a
stable v5 release.

## Current gate status

| Gate | Required state | Current evidence | Status |
| --- | --- | --- | --- |
| Protocol | A published stable revision, not `draft` | The latest stable specification is `2025-11-25`; the proposed `2026-07-28` revision is still under `/specification/draft` | Blocked |
| Kotlin SDK | Released server transport for the modern wire | Kotlin SDK `0.14.0` is latest; issue #815 is open and PR #893 adds core types only, explicitly excluding server admission, dispatch, HTTP, subscriptions, and lifecycle | Blocked |
| Conformance | Released modern server suite with stable expectations | `0.1.16` is the stable legacy suite; modern checks remain in the `0.2.0-alpha.9` line and repository main | Blocked |
| Clients | Stable releases from the supported client matrix | TypeScript SDK v2 is beta and still has open modern-era compatibility issues; other supported clients require explicit verification | Blocked |
| Approval lifecycle | A safe replacement for connection-scoped grants | The modern protocol removes protocol sessions; client identity metadata is self-reported and cannot authorize or key approval state | Design required |
| Burp scale | Measured behavior on large live projects | Synthetic probes exist, but live 10k/50k/100k histories and issue sets are not yet complete | Open |

Upstream references:

- [MCP current stable specification](https://modelcontextprotocol.io/specification)
- [Draft Streamable HTTP](https://modelcontextprotocol.io/specification/draft/basic/transports/streamable-http)
- [Draft versioning and compatibility](https://modelcontextprotocol.io/specification/draft/basic/versioning)
- [Kotlin SDK 2026-07-28 tracker](https://github.com/modelcontextprotocol/kotlin-sdk/issues/842)
- [Kotlin SDK stateless tracker](https://github.com/modelcontextprotocol/kotlin-sdk/issues/815)
- [Kotlin SDK request-metadata and discovery types PR](https://github.com/modelcontextprotocol/kotlin-sdk/pull/893)

## Expected modern wire changes

The current draft is not merely a session optimization. It changes the protocol lifecycle and result model:

- `initialize` and `notifications/initialized` are removed.
- `server/discover` is mandatory.
- Every request carries protocol version, client capabilities, and optional client identity in `_meta`.
- Streamable HTTP is POST-only. Protocol GET and DELETE are removed; `/mcp` returns `405` for them.
- `Mcp-Session-Id` and protocol-level session state are removed.
- `MCP-Protocol-Version`, `Mcp-Method`, and conditional `Mcp-Name` headers must match the JSON body.
- Ordinary results carry `resultType: "complete"`; modern cacheable results also carry `ttlMs` and `cacheScope`.
- Request-scoped SSE remains valid for progress and related notifications. “Sessionless” does not mean strictly
  JSON-only.
- Long-lived change notifications move to a POST response stream opened by `subscriptions/listen`.
- HTTP cancellation is the closing of that request's SSE response stream. Stdio cancellation remains
  `notifications/cancelled`.
- Server-initiated requests are replaced by Multi Round-Trip Request results.

These requirements must be implemented by the official SDK or by an independently approved transport architecture.
This project will not add a partial raw JSON-RPC fork beside the SDK merely to claim draft compatibility.

## Safety migration decisions

The following constraints carry into v5:

- Numeric-loopback binding, bearer authentication, strict Host/Origin checks, request bounds, and redirect denial stay
  mandatory.
- Self-reported `clientInfo` must not be used for authentication, authorization, rate-limit partitioning, audit identity,
  or approval grants.
- Connection-scoped approval grants cannot silently become installation-wide grants. The safe default for modern mode is
  to disable those grants and retain per-operation approval plus explicit persistent policies.
- Any future explicit approval handle must be random, bounded, short-lived, operation-class-specific, revocable, and
  separately reviewed. It must not carry targets, traffic, project IDs, or client-provided values.
- Ambiguous state-changing results remain non-retryable.
- Diagnostics remain fixed-cardinality and value-redacted.
- The Professional and Community catalogs remain 26 and 19 tools unless a separately reviewed major-version catalog
  change has concrete user value.

## Implementation stages

### Stage A — production hardening while gates are closed

1. Keep v4 on stable `2025-11-25` and update its stable conformance runner without changing runtime behavior.
2. Complete client/session soak tests, cancellation/disconnect tests, and live 10k/50k/100k Burp measurements.
3. Validate context-menu fallback timing and fail-closed behavior at the same live scales.
4. Track Kotlin SDK server transport, cancellation, request-ID, and CIO shutdown work upstream.
5. Validate resource/prompt rendering and discovery across the supported clients.

### Stage B — private v5 candidate after SDK support exists

1. Build from an exact released SDK version and a published protocol revision.
2. Implement mandatory discovery, per-request metadata, mirrored-header validation, modern errors, result discriminators,
   and cache metadata.
3. Remove GET, DELETE, session IDs, session registries, idle/pressure eviction, and legacy handshake behavior from the
   modern endpoint.
4. Bind each HTTP response stream directly to its request coroutine so disconnect cancellation reaches bounded Burp work
   where cancellation is safe.
5. Keep resource subscriptions disabled unless their project/source policy and bounded notification lifecycle are proven.
6. Run modern conformance with no whole-scenario expected-failure entry.

### Stage C — interoperability and migration

1. Verify the exact tools/resources/templates/prompts surface against every supported client.
2. Decide, from measured client support, whether v5 is modern-only or dual-era. Dual-era support is not assumed: it
   increases admission, approval, audit, and shutdown complexity.
3. Publish explicit v4-to-v5 migration guidance. v4 remains the compatibility line for legacy clients.
4. Repeat live Burp Professional and Community validation with release-candidate bytes.

### Stage D — stable release gate

A stable `v5.0.0` tag may be created only when all of the following are true:

- the protocol revision and Kotlin SDK support are stable releases;
- modern conformance passes without a whole-scenario baseline;
- at least the supported native HTTP client and embedded stdio proxy pass the release matrix;
- cancellation, progress, approval, audit, and shutdown behavior have bounded live evidence;
- 10k/50k/100k measurements have no unreviewed EDT or memory regression;
- two clean exact-commit JAR/SBOM builds are byte-identical;
- OSV, Dependabot, archive inspection, checksums, and provenance pass;
- a draft release is independently verified before the annotated tag and publication.

Until those gates close, v5 work is a readiness branch or prerelease candidate, not a production compatibility claim.
