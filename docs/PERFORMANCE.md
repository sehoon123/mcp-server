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
| P1 | Cross-source HTTP discovery could require full-message output or unbounded regex scans | Existing list tools expose raw offset pagination and legacy regex filters | Add compact literal/field search with signed cursors, a 50-result cap, a 10,000-record scan budget, and a 32 MiB content budget |
| P1 | Content-search accounting ran before cheaper metadata filters | Host/method/status mismatches still queried message sizes and consumed the 32 MiB budget | Compile membership filters once and apply all metadata predicates before content sizing or scanning |
| P1 | Stable-ID reads constructed complete Proxy/WebSocket/Organizer snapshots | A one-record lookup called the unfiltered list API and then searched locally | Use Montoya's filtered lookup overloads and return at most matching records |
| P1 | Derived request actions could materialize and repeatedly parse a request | Exact replay needs a size check, but text is needed only for interactive approval; individual parameter edits repeatedly rebuild immutable requests | Compute size from header/body lengths without a full byte array, lazily render request text, and batch parameter removal/addition per patch |
| P1 | Raw HTTP prelude normalization made up to five full intermediate strings | A request passed through chained global `replace` calls | Normalize escapes and line endings in one bounded pass; preserve body bytes verbatim |
| P1 | Auto-approved targets were split and trimmed on every outbound request | Approval checks reparsed an unchanged persisted string | Cache the parsed immutable target list until its raw setting changes |
| P2 | Legacy user-supplied Java regexes scan complete Burp histories and have no time budget | A pathological pattern can monopolize CPU | Migrate clients to bounded literal search and add a constrained regex policy |

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

## Bounded unified HTTP search

`search_http_messages` takes one source snapshot per call and applies metadata filters before notes, stable Site Map
fingerprints, or result serialization. A page returns at most 50 compact records. Work that finds few or no matches is
also bounded: each call examines at most 10,000 metadata records, and literal request/response searches inspect at most
32 MiB of message data. A single message larger than that content budget is advanced past and reported through
`oversizedContentSkipped`, preventing an infinite cursor loop.

The continuation cursor records the next raw source index rather than a count of matched results. Deep pages therefore
resume filtering where the previous page stopped instead of rescanning all earlier candidates. Cursors are HMAC-signed,
query- and project-bound, and capture source sizes plus boundary anchors. Appended records are excluded from an active
snapshot; a cleared or boundary-reordered source fails with `stale_cursor`. Montoya still creates each requested source
list, but skipped records are never converted to JSON or full byte arrays.

Site Map IDs combine the original list index with a bounded identity fingerprint. Normal lookup validates that index in
O(1); it does not hash every Site Map message. Fingerprints sample bounded request/response metadata and body regions,
so very large bodies do not cause proportional ID-generation allocation.

Metadata predicates now run before content accounting. A host, path, method, status, MIME, scope, or response-presence
mismatch performs no body-size query and consumes none of the 32 MiB content budget. Method, status, and MIME lists are
compiled to hash sets once per call rather than searched linearly for every candidate. Regression tests verify zero
`bodyOffset`, body scan, note, fingerprint, and serialization calls for the relevant rejected records.

## Stable-ID lookup and action hot paths

Proxy HTTP, Proxy WebSocket, and Organizer get-by-ID paths use Montoya's filtered overloads. Montoya may still inspect
its internal store, but the extension no longer asks it to construct and return a complete list before selecting one
record. Site Map keeps positional validation because its opaque ID deliberately fails closed after removal or reorder
and Montoya exposes no direct stable-ID lookup.

Stable-ID request actions cap source and resulting requests at 2 MiB. Exact replay computes byte length from
`bodyOffset + body.length` and does not materialize a complete byte array. Request text is held behind a non-thread-safe
lazy value scoped to the invocation: when action approval is disabled,
or HTTP approval is disabled/auto-approved, the potentially large string is never created. Parameter replacements are
resolved once per affected parameter type and applied as at most one removal plus one addition, rather than reparsing and
rebuilding the immutable request for every mutation. Response previews slice the Montoya byte array before text/base64
conversion and are capped at 64 KiB. A 100 ms–120 s Montoya response timeout bounds response reading without wrapping
an ambiguously delivered request in an unsafe coroutine retry.

Existing raw HTTP/1.1, Repeater, and Intruder tools retain their output but now normalize request preludes in one pass
instead of up to five complete replacement passes. Bodies remain untouched. HTTP/2 header construction reuses its
ordered map rather than allocating a second merged map. The parsed auto-approval target list is also reused until the
persisted raw value changes.

A standalone Java 21 `ThreadMXBean` probe compared the previous replacement/substrings pipeline with the current
compiled `normalizeHttpContent` implementation. After warm-up, the median of nine alternating rounds was:

| Input | Previous median / allocation | One-pass median / allocation | Allocation reduction |
|---|---:|---:|---:|
| 1 MiB body after a 3 KiB escaped prelude | 1.65 ms / 3,165,616 B | 1.57 ms / 2,103,648 B | 33.5% |
| 256 KiB escaped prelude, no body | 0.98 ms / 1,039,736 B | 1.00 ms / 494,064 B | 52.5% |

Latency is effectively neutral for the header-only synthetic case and about 5% lower for the large-body case; the
reliable gain is fewer temporary strings and substantially lower allocation. Both paths produced identical output,
including byte-for-byte preservation of body text.

## Reproducible packaging

The extension manifest previously included build time, user, JDK, and Gradle fields, and `embedProxyJar` mutated the
completed Shadow JAR through the platform `jar` command. Both paths introduced timestamps outside Gradle's reproducible
archive controls. The proxy and extension now disable file timestamps, use reproducible entry ordering, add the nested
proxy as a normal Shadow input, and stream-verify the source and embedded SHA-256. Two clean reruns from identical
inputs must produce byte-identical proxy and extension JARs.

## Deferred changes that affect behavior or APIs

The first feature phase added compact stable-ID summaries and bounded field reads. New detail tools avoid converting
complete HTTP/WebSocket messages, return MCP structured content, and expose explicit byte-slice metadata. The
following work remains:

1. Cap or validate legacy pagination `count` and `offset` to prevent unbounded output requests.
2. Migrate legacy source-specific list tools to the signed cursor model.
3. Make compact summaries the default after a compatibility window and replace post-serialization 5,000-character truncation with a streaming/capped encoder.
4. Paginate and bound Collaborator interaction output.
5. Add hard timeouts to remaining long-running read/config tools without treating an ambiguous mutation as retryable.
6. Add a constrained regex mode; new unified search intentionally supports bounded literal matching only.
7. Add event-backed, project-bounded ID indexes where Montoya lifecycle events can prove that cached entries are still live.
8. Add idle session expiry for native clients that do not terminate Streamable HTTP sessions.

## Regression checks

Performance changes should preserve the following:

- Only selected page items invoke serialization.
- Unified search never exceeds its result, metadata-scan, content-scan, cursor, URL, or note bounds.
- Metadata-rejected search records never consume content budget or invoke body scans.
- Stable-ID Proxy/WebSocket/Organizer readers use filtered lookup APIs instead of full returned snapshots.
- Derived request actions render full request text only when an interactive approval needs it.
- Signed search cursors reject tampering, project changes, and stale source boundaries.
- Approval cancellation remains a coroutine cancellation rather than a tool error.
- Server stop/restart closes all SDK sessions.
- Proxy graceful shutdown sends DELETE when a session exists, but never blocks shutdown for more than two seconds.
- Proxy request concurrency and pending queues remain bounded under bursts; rejected requests are never forwarded.
- Ambiguous post-send failures never retry arbitrary or custom requests.
- Existing proxy extraction is skipped without reading the nested JAR.
- Repeated builds from identical inputs produce byte-identical proxy and extension JARs.
- Tool output remains byte-for-byte compatible for valid existing requests.
