# Performance analysis

This analysis covers the Streamable HTTP server and the embedded stdio proxy. The probes below are synthetic and are
intended to expose algorithmic behavior; they are not Burp Suite product benchmarks.

## Summary

| Priority | Finding | Evidence | Optimization |
|---|---|---|---|
| P0 | Deep pagination serialized every skipped record | 18,010 serializations for a 10-item page at offset 18,000 | Apply offset/count before mapping and serialization |
| P0 | Approval waits used `runBlocking` inside request handlers | A four-thread probe completed 20 waits in 1,038 ms instead of 209 ms | Make tool callbacks suspend and execute blocking Burp work on a bounded IO dispatcher |
| P0 | Graceful Streamable HTTP client close retained server sessions | 20 connect/close cycles retained 20 sessions; explicit DELETE retained 0 | Terminate the proxy's HTTP session and close the MCP server during lifecycle transitions |
| P1 | Extension startup read and allocated the complete 14.7 MB proxy JAR even when unchanged | `mcp-proxy-all.jar` is 14,725,972 bytes | Read the embedded checksum metadata first and stream the JAR only when extraction is required |
| P1 | Result-size limits are applied after full message conversion and JSON serialization | Large request/response bodies are converted before the 5,000-character cut | Address with bounded structured output in the feature phase |
| P1 | Proxy launched one coroutine per incoming stdio message without an admission limit | A burst could accumulate suspended request coroutines during reconnect | Use bounded request/control/lifecycle queues and a fixed request worker pool |
| P1 | Build metadata and post-build `jar uf` mutation made extension bytes change on every build | Identical sources produced artifacts with different timestamps and manifest values | Package the proxy through Gradle's reproducible archive pipeline and verify embedded provenance |
| P2 | User-supplied Java regexes scan complete Burp histories and have no time budget | A pathological pattern can monopolize CPU | Add safe search modes or a bounded regex policy in the feature phase |

## Pagination probe

The current pipeline had this effective order:

```kotlin
items.asSequence()
    .map(::serialize)
    .drop(offset)
    .take(count)
```

A local JVM probe used 20,000 records with a shared 4,096-character payload, `offset=18_000`, and `count=10`.
Allocation was measured with `com.sun.management.ThreadMXBean` after warm-up; the median of five runs is shown.

| Pipeline | Median | Thread allocation | Records serialized |
|---|---:|---:|---:|
| Map, then drop | 25.75 ms | 142.4 MiB | 18,010 |
| Drop, then map | 0.25 ms | 0.401 MiB | 10 |

The optimized probe produced the same output checksum. The approximately 103x latency and 355x allocation differences
apply to this intentionally deep synthetic page. Real results depend on history size and message bodies, but the old
algorithm always performed `offset + count` mappings while the new one performs at most `count` mappings.

The Montoya API still returns a complete history snapshot and does not expose native cursor pagination, so retrieving
and advancing through that list remains O(history size/offset). Stable IDs or a maintained index are feature-level
improvements considered separately.

## Blocking approval probe

Tool callbacks were non-suspending and called `runBlocking` around Swing approval functions. Human approval suspends
logically, but `runBlocking` keeps the request worker occupied for the entire dialog lifetime.

A probe dispatched 20 simulated 200 ms approval waits to four worker threads:

| Path | Completion time |
|---|---:|
| `runBlocking { delay(...) }` | 1,038 ms |
| Direct suspending `delay(...)` | 209 ms |

The five-fold difference follows the number of worker waves in this setup. A real dialog can remain open for seconds
or minutes, making starvation more severe. Tool callbacks are therefore suspending, while blocking Montoya operations
run on a bounded `Dispatchers.IO` view so Ktor/MCP request processing threads remain available.

## Session retention probe

The MCP Kotlin SDK's `Client.close()` closes the local transport but does not send Streamable HTTP `DELETE`. The server
transport manager removes a stateful session on DELETE or server shutdown, not when the optional GET event stream
disconnects.

A real SDK/Ktor probe produced:

```text
sessions after 20 Client.close() calls: 20
additional sessions retained after 20 terminateSession()+close(): 0
```

Each retained server session also owns notification bookkeeping. The packaged proxy now calls `terminateSession()`
with a short timeout during graceful shutdown, and `KtorServerManager` explicitly closes the MCP `Server` whenever it
stops or replaces the Ktor engine.

Native third-party clients that never issue DELETE can still leave sessions until the Burp MCP server restarts. A
server-side idle-session policy requires either an SDK enhancement or a custom transport manager and is intentionally
not introduced as part of this behavior-preserving pass.

## Embedded proxy extraction

Before this pass, every extension initialization performed:

```kotlin
resourceStream.readAllBytes()
sha256(resourceBytes)
```

This allocated at least the complete 14.7 MB nested JAR, even when the already-extracted version was current. The
packaged `mcp-proxy-source.txt` already contains the trusted SHA-256. Startup now reads that small metadata first and
returns immediately when the version marker matches. When an update is required, a `DigestInputStream` verifies the
JAR while copying it to disk, avoiding the full in-memory byte array.

## Proxy request backpressure and retry safety

The stdio transport already bounds raw frame and output buffering, but the proxy previously detached every decoded
message into a new coroutine. A disconnected Burp instance or slow approval could therefore accumulate an unbounded
number of suspended relays. The proxy now separates lifecycle, normal request, and control traffic into bounded
channels. Sixteen request workers consume a 64-request queue. Once that admission budget is full, another request is
rejected with an immediate not-forwarded JSON-RPC error instead of allocating another coroutine or delaying
initialized/cancellation/response traffic.

The retry decision is also split by delivery phase. Connection establishment can retry transient availability
failures because the current message has not been sent. After send, only a definitive missing-session 404, a refused
TCP connection, or an initialization-only transient failure is retried. Arbitrary and custom requests are not retried
after parser, transport, or server failures whose delivery status is ambiguous.

## Reproducible packaging

The extension manifest previously included build time, user, JDK, and Gradle fields, and `embedProxyJar` mutated the
completed Shadow JAR through the platform `jar` command. Both paths introduced timestamps outside Gradle's reproducible
archive controls. The proxy and extension now disable file timestamps, use reproducible entry ordering, add the nested
proxy as a normal Shadow input, and stream-verify the source and embedded SHA-256. Two clean reruns from identical
inputs must produce byte-identical proxy and extension JARs.

## Deferred changes that affect behavior or APIs

These items should be handled in the feature phase with explicit schemas and compatibility tests:

1. Cap or validate pagination `count` and `offset` to prevent unbounded output requests.
2. Add stable history IDs, cursor pagination, field selection, and per-field body limits.
3. Avoid converting entire HTTP messages before limiting output; return valid structured JSON plus truncation metadata.
4. Paginate Collaborator interactions and bound Scanner issue evidence.
5. Add configurable hard request timeouts and cancellation without breaking long approval waits.
6. Add safe literal/field search and a constrained regex mode.
7. Add idle session expiry for native clients that do not terminate Streamable HTTP sessions.

## Regression checks

Performance changes should preserve the following:

- Only selected page items invoke serialization.
- Approval cancellation remains a coroutine cancellation rather than a tool error.
- Server stop/restart closes all SDK sessions.
- Proxy graceful shutdown sends DELETE when a session exists, but never blocks shutdown for more than two seconds.
- Proxy request concurrency and pending queues remain bounded under bursts; rejected requests are never forwarded.
- Ambiguous post-send failures never retry arbitrary or custom requests.
- Existing proxy extraction is skipped without reading the nested JAR.
- Repeated builds from identical inputs produce byte-identical proxy and extension JARs.
- Tool output remains byte-for-byte compatible for valid existing requests.
