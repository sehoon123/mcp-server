# v5 protocol readiness

**Status date:** 2026-07-24

Version 5 is reserved for the first production release that adopts the modern, per-request MCP protocol era. The current
production release is v4.5.0 on stable protocol `2025-11-25`. A draft or an SDK branch is not sufficient authority for a
stable v5 release.

## PM transition decision

The migration is gate-driven, not date-driven. Publication of a revision named `2026-07-28` would satisfy only the
protocol gate; it would not by itself authorize a production migration. The current decision is **NO-GO for a production
v5 endpoint** and **GO for Stage A design, compatibility spikes, and v4 hardening**.

| Release stage | Entry condition | Exposure |
| --- | --- | --- |
| Stage A — now | Upstream gates are still open | v4 production changes and isolated, non-production spikes only |
| Private v5 alpha | Stable protocol plus a released official Kotlin modern server transport and the approval baseline | Private branch/build; no compatibility claim |
| v5 beta/RC | Modern conformance passes without a whole-scenario waiver and the supported client matrix works | Explicit prerelease only |
| Stable v5 | Every release gate below plus a 14-day RC period with no unresolved P0/P1 defect | Annotated `v5.0.0` and public production release |

Production main remains on the v4 compatibility line until the private candidate proves that moving it is safer than a
separate modern line. A partial raw JSON-RPC implementation is not an acceptable shortcut.

## Current gate status

| Gate | Required state | Current evidence | Status |
| --- | --- | --- | --- |
| Protocol | A published stable revision, not `draft` | The latest stable specification is `2025-11-25`; the proposed `2026-07-28` revision is still under `/specification/draft` | Blocked |
| Kotlin SDK | Released server transport for the modern wire | Kotlin SDK `0.14.0` is latest; issue #815 is open and PR #893 adds core types only, explicitly excluding server admission, dispatch, HTTP, subscriptions, and lifecycle | Blocked |
| Conformance | Released modern server suite with stable expectations | `0.1.16` is the stable legacy suite; modern checks remain in the `0.2.0-alpha.9` line and repository main | Blocked |
| Clients | Stable releases from the supported client matrix | TypeScript SDK v2 is beta and still has open modern-era compatibility issues; other supported clients require explicit verification | Blocked |
| Approval lifecycle | A safe replacement for connection-scoped grants | [V5_APPROVAL_MODEL.md](V5_APPROVAL_MODEL.md) defines a fail-safe no-session-grant baseline; implementation and client evidence remain open | Partial |
| Burp scale | Measured behavior on large live projects | Real isolated Community Site Map paths are measured at 10k/50k/100k with synthetic data; Proxy, Organizer, WebSocket, Professional Scanner, context-menu, and soak evidence remain open | Partial |

Upstream references:

- [MCP current stable specification](https://modelcontextprotocol.io/specification)
- [Draft Streamable HTTP](https://modelcontextprotocol.io/specification/draft/basic/transports/streamable-http)
- [Draft versioning and compatibility](https://modelcontextprotocol.io/specification/draft/basic/versioning)
- [Kotlin SDK 2026-07-28 tracker](https://github.com/modelcontextprotocol/kotlin-sdk/issues/842)
- [Kotlin SDK stateless tracker](https://github.com/modelcontextprotocol/kotlin-sdk/issues/815)
- [Kotlin SDK request-metadata and discovery types PR](https://github.com/modelcontextprotocol/kotlin-sdk/pull/893)
- [Montoya API 2026.7 release](https://github.com/PortSwigger/burp-extensions-montoya-api/releases/tag/2026.7)

## Montoya integration lane

Montoya is a separate product-runtime decision, not evidence that the MCP wire is ready. The production extension remains
compiled against Montoya `2025.10`. Compared with that pin, the published `2026.7` API exposes typed/table HotKey
registration and an HTTP request execution engine with an explicit `RequestExecutionLifetime.cancel()` lifecycle. The
request engine was introduced in `2026.7` and is Professional-only. These APIs do not replace MCP discovery, per-request
metadata, conformance, client support, or the sessionless approval design.

An isolated version-catalog-only spike at exact v4.5.0 commit
`d477d08fe5c23b9b3b94a8b075cd7c234d0dd03e` compiled against `2026.7` and passed all 408 tests. Its extension JAR stayed
byte-identical because Montoya is compile-only and no new API was used. This proves source compatibility only; it does not
prove matching Burp runtime behavior, minimum-platform compatibility, or value from the new APIs.

The safe sequence is:

1. compile and test the unchanged v4 code against `2026.7` in an isolated worktree — completed for source compatibility;
2. live-test a private build on matching Burp Community and Professional runtimes;
3. quantify the minimum supported Burp-version change and BApp compatibility impact;
4. build the first modern-wire alpha against the known `2025.10` baseline so transport defects are attributable;
5. add `2026.7` in a later private alpha only if its cancellation or HotKey APIs provide concrete reviewed value;
6. merge the dependency and minimum-version change only after both tracks pass independently.

No high-risk feature becomes approved merely because a newer Montoya API exposes it.

### Partial Burp-scale evidence

The Community Site Map portion of this gate now has a real isolated Burp 2026.6 run at 10,000, 50,000, and 100,000
synthetic bounded request/response records. MCP revalidated each source count. The run includes JFR-enabled latency,
separate whole-process allocation upper bounds, working set/private bytes, post-GC heap context, and sampled EDT
watchdog diagnostics. At 100k, the recent search still returned and logically scanned 50 records, but its p50 was
73.323 ms and its whole-process allocation upper bound was 161.171 MiB/call. The pattern is consistent with acquiring a
complete Montoya Site Map returned list before bounded extension processing; an API-only probe is still needed for
precise attribution.

The 100k context-menu sub-gate is not complete. Exact process/window targeting reached the isolated Burp instance, but
built-in Site Map activation repeatedly failed in Burp's internal tab-selection path, including a fresh zero-record
control before the MCP suite tab was registered. No menu-open latency, Copy action latency, or copied URI from that
100k UI route was accepted. Proxy history, Organizer, WebSocket history, Professional Scanner, and long-duration
multi-client soak are also unmeasured. See [PERFORMANCE.md](PERFORMANCE.md#isolated-live-site-map-scale-run) for the
measurements, instrumentation limits, hashes, and non-generalization rules.

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
2. Use [V5_APPROVAL_MODEL.md](V5_APPROVAL_MODEL.md) as the security baseline and keep modern transient grants disabled.
3. Normalize cancellation, timeout, partial-completion, and uncertain structured results without claiming unsupported
   wire cancellation.
4. Run the isolated Montoya `2026.7` compile/test spike, but do not change the production dependency or minimum Burp
   version without separate live evidence.
5. Design project-bound list changes and subscriptions so a project transition closes stale delivery before new-project
   data can appear.
6. Validate resource/prompt rendering, discovery, restart behavior, and protocol fallback across supported clients.
7. Track Kotlin SDK server transport, cancellation, request-ID, task, and CIO shutdown work upstream.
8. Retain the remaining scale, context-menu, and multi-client soak work as RC gates rather than displacing the current
   feature/security work.

The schema-preserving foundation for item 3 is implemented after v4.5.0: existing mutation families retain their public
status fields while sharing bounded reconciliation guidance for uncertain execution, treating timeouts reported by Burp's
synchronous execution API after dispatch as uncertain, and preserving cancellation exceptions. Scanner target submission now checks cancellation between bounded
targets and attempts to remove an unreturned extension-owned task. This does not close the wire-cancellation gate, add a
new public timeout discriminator, or imply cancellation support in Burp APIs that expose no lifetime handle.

### Stage B — private v5 candidate after SDK support exists

1. Build from an exact released SDK version and a published protocol revision.
2. Build the first modern-wire alpha against Montoya `2025.10` to isolate the transport migration.
3. Implement mandatory discovery, per-request metadata, mirrored-header validation, modern errors, result discriminators,
   and cache metadata.
4. Remove GET, DELETE, session IDs, session registries, idle/pressure eviction, and legacy handshake behavior from the
   modern endpoint.
5. Apply the no-transient-grant approval baseline and prove that connection, stdio process, request ID, and self-reported
   client metadata cannot carry authority between requests.
6. Bind each HTTP response stream directly to its request coroutine so disconnect cancellation reaches bounded Burp work
   where cancellation is safe.
7. Keep resource subscriptions disabled unless their project/source policy and bounded notification lifecycle are proven.
8. Run modern conformance with no whole-scenario expected-failure entry.
9. Evaluate a later private alpha on Montoya `2026.7`; do not combine the two migrations in the first diagnostic build.

### Stage C — interoperability and migration

1. Verify the exact tools/resources/templates/prompts surface against every supported client.
2. Decide, from measured client support, whether v5 is modern-only or dual-era. Dual-era support is not assumed: it
   increases admission, approval, audit, and shutdown complexity.
3. Decide whether the Montoya baseline changes, using separate transport and runtime evidence plus the minimum supported
   Burp-version impact.
4. Publish explicit v4-to-v5 migration guidance. v4 remains the compatibility line for legacy clients.
5. Repeat live Burp Professional and Community validation with release-candidate bytes.

### Stage D — stable release gate

A stable `v5.0.0` tag may be created only when all of the following are true:

- the protocol revision and Kotlin SDK support are stable releases;
- modern conformance passes without a whole-scenario baseline;
- at least the supported native HTTP client and embedded stdio proxy pass the release matrix;
- cancellation, progress, approval, audit, and shutdown behavior have bounded live evidence;
- the release candidate completes at least 14 days with no unresolved P0/P1 defect;
- any Montoya/minimum-Burp change has independent Community and Professional compatibility evidence;
- 10k/50k/100k measurements have no unreviewed EDT or memory regression;
- two clean exact-commit JAR/SBOM builds are byte-identical;
- OSV, Dependabot, archive inspection, checksums, and provenance pass;
- a draft release is independently verified before the annotated tag and publication.

Until those gates close, v5 work is a readiness branch or prerelease candidate, not a production compatibility claim.
