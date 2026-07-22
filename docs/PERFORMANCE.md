# Performance analysis

This analysis covers the Streamable HTTP server and the embedded stdio proxy. The probes below are synthetic and are
intended to expose algorithmic behavior; they are not Burp Suite product benchmarks.

## Summary

| Priority | Finding | Evidence | Optimization |
|---|---|---|---|
| P0 | Deep pagination serialized every skipped record | 18,010 serializations for a 10-item page at offset 18,000 | Apply offset/count before mapping and serialization |
| P0 | Approval waits used `runBlocking` inside request handlers | A four-thread probe completed 20 waits in 1,038 ms instead of 209 ms | Make tool callbacks suspend and execute blocking Burp work on a bounded IO dispatcher |
| P0 | Graceful Streamable HTTP client close retained server sessions | 20 connect/close cycles retained 20 sessions; explicit DELETE retained 0 | Terminate the proxy's HTTP session and close the MCP server during lifecycle transitions |
| P0 | Ephemeral native clients could exhaust all 32 sessions after disconnecting their optional SSE streams without DELETE | Repeated mcporter commands eventually returned `MCP session capacity is full` | Prefer one keep-alive client session and displace only the least-recently-used inactive disconnected-stream session under capacity pressure |
| P0 | CIO wrapped an occupied listener in `JobCancellationException` | A real occupied-port regression reached `BindException` only after two cancellation causes | Recognize the bounded cause chain, report the numeric endpoint conflict, and verify retry after cleanup |
| P1 | A disconnected optional GET SSE stream could retain a concurrent HTTP slot | A live JS SDK close left the server socket in `CLOSE_WAIT` and the active-call counter nonzero | Track the handler job, cancel it on session close, and emit a comment-only heartbeat to detect a dead peer |
| P1 | Extension startup read and allocated the complete embedded proxy JAR even when unchanged | The v2.1.0 `mcp-proxy-all.jar` is 14,739,644 bytes | Read trusted checksum metadata first, stream-verify the existing file, and stream the nested JAR only when extraction is required |
| P1 | Legacy result-size limits were applied after full message conversion and JSON serialization | Large request/response bodies were converted before a 5,000-character mid-JSON cut | Return summary-first complete records with bounded single-field previews and explicit page truncation metadata |
| P1 | Proxy launched one coroutine per incoming stdio message without an admission limit | A burst could accumulate suspended request coroutines during reconnect | Use bounded request/control/lifecycle queues and a fixed request worker pool |
| P1 | Build metadata and post-build `jar uf` mutation made extension bytes change on every build | Identical sources produced artifacts with different timestamps and manifest values | Package the proxy through Gradle's reproducible archive pipeline and verify embedded provenance |
| P1 | Cross-source HTTP discovery could require full-message output or unbounded regex scans | Existing list tools expose raw offset pagination and legacy regex filters | Add compact literal/field search with signed cursors, a 50-result cap, a 10,000-record scan budget, and a 32 MiB content budget |
| P1 | Repeated attack-surface discovery re-read source metadata and encouraged model-side aggregation | Montoya exposes source lists but no project-wide metadata index | Retain at most 5,000 body-free records per source, validate bounded anchors, discard on project changes, and build exact top summaries without per-key detail maps |
| P1 | Content-search accounting ran before cheaper metadata filters | Host/method/status mismatches still queried message sizes and consumed the 32 MiB budget | Compile membership filters once and apply all metadata predicates before content sizing or scanning |
| P1 | Stable-ID reads constructed complete Proxy/WebSocket/Organizer snapshots | A one-record lookup called the unfiltered list API and then searched locally | Use Montoya's filtered lookup overloads and return at most matching records |
| P1 | Derived request actions could materialize and repeatedly parse a request | Exact replay needs a size check, but text is needed only for interactive approval; individual parameter edits repeatedly rebuild immutable requests | Compute size from header/body lengths without a full byte array, lazily render request text, batch parameter mutations, and resolve semantic Intruder insertion points once |
| P1 | Scanner, comparison, issue filtering, and Collaborator workflows could expose unbounded data or model-side polling | Native lists and task details can grow with a project | Cap references, targets, inspected bytes, issue scans/results, interaction scans/details, concurrent waits, and retained Scanner task handles |
| P1 | Raw HTTP prelude normalization made up to five full intermediate strings | A request passed through chained global `replace` calls | Normalize escapes and line endings in one bounded pass; preserve body bytes verbatim |
| P1 | Auto-approved targets were split and trimmed on every outbound request | Approval checks reparsed an unchanged persisted string | Cache the parsed immutable target list until its raw setting changes |
| P2 | Legacy user-supplied Java regexes could scan complete Burp histories without a time budget | A pathological pattern could monopolize CPU | Prefer bounded literal search and enforce a 512-character conservative regex grammar |
| P2 | Per-tool durable audit writes could amplify persistence I/O during bursts | Up to 16 tool handlers may finish concurrently | Retain only bounded value-free records and debounce serialized extension-data writes by 250 ms |

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

The server additionally wraps SDK transports in a bounded registry. At most 32 pending or active sessions can exist;
idle sessions are evicted after 15 minutes by a 60-second sweep. Explicit DELETE, initialization failure, capacity
rejection, idle eviction, and application shutdown all close a transport exactly once. Shutdown waits at most two
seconds for aggregate session cleanup, so a stalled SDK close cannot indefinitely block listener restart.

Native third-party clients that omit DELETE therefore consume a slot until normal idle eviction unless capacity is
needed first. Under capacity pressure, the registry may displace only the least-recently-used inactive session that
previously registered an optional GET event stream and whose stream has disconnected. It never pressure-evicts a
session with an active call, an open event stream, or no observed stream. The displaced transport is closed with a
bounded cleanup before the replacement initializes; if no eligible session exists, the new transport is rejected and
closed immediately. A real-CIO regression uses a short test heartbeat to close two optional streams, initializes a
replacement at the configured limit, verifies the oldest session returns 404, and verifies the newer session remains
usable. Against the real CIO fixture, 40 sequential mcporter `ephemeral` discovery processes (spaced 500 ms so closed
peers reached the production heartbeat) and 100 rapid `keep-alive` daemon discoveries both completed without a
capacity rejection. Keep-alive remains the recommended mode because a burst faster than disconnect detection can still
consume the fixed admission budget temporarily.

CIO reports an occupied startup connector through cancellation wrappers whose bounded cause chain ends in
`BindException`. Startup now recognizes that specific root cause and reports only the numeric local endpoint and that
it is already in use; no credential, path, or raw coroutine diagnostic is retained. Closing the MCP server may also
cancel its own transport jobs. Explicit stop treats that as successful only when the bounded cause chain contains no
non-cancellation failure. Regression tests release the occupied socket, retry the same manager, and exercise a complete
start/stop/start cycle against a real listener.

## Embedded proxy extraction

Before this pass, every extension initialization performed:

```kotlin
resourceStream.readAllBytes()
sha256(resourceBytes)
```

This allocated at least the complete 14.7 MB nested JAR, even when the already-extracted version was current. The
packaged `mcp-proxy-source.txt` contains the trusted SHA-256. Startup reads that small metadata first and
stream-verifies the existing extracted JAR even when its version marker matches, so marker-only tampering cannot bypass
validation. Only a missing or mismatched file causes the nested resource to be streamed to an atomic replacement;
neither path allocates the complete JAR in memory.

## Proxy request backpressure and retry safety

The stdio transport already bounds raw frame and output buffering, but the proxy previously detached every decoded
message into a new coroutine. A disconnected Burp instance or slow approval could therefore accumulate an unbounded
number of suspended relays. The proxy now separates lifecycle, normal request, and control traffic into bounded
channels. Sixteen request workers consume a 64-request queue. Once that admission budget is full, another request is
rejected with an immediate not-forwarded JSON-RPC error instead of allocating another coroutine or delaying
initialized/cancellation/response traffic. A `notifications/cancelled` message also cancels a matching queued or active
forwarding coroutine before being relayed upstream; cancellation cannot strand the sole worker behind an inline HTTP
response, and unknown cancellation IDs do not allocate retained state.

The retry decision is also split by delivery phase. Connection establishment can retry transient availability
failures because the current message has not been sent. After send, only a definitive missing-session 404, a refused
TCP connection, or an initialization-only transient failure is retried. Arbitrary and custom requests are not retried
after parser, transport, or server failures whose delivery status is ambiguous.

## Authenticated and bounded HTTP endpoint

The production listener binds only to numeric loopback (`127.0.0.1` or `::1`) and exposes one `/mcp` endpoint. Every
production request requires the per-installation bearer token; strict Host and Origin checks are independent browser
hardening rather than an authentication substitute. The endpoint rejects requests before MCP decoding when any of the
following admission limits are exceeded:

| Resource | Limit |
|---|---:|
| Request body | 2 MiB |
| Request URI | 8,192 characters |
| Header fields | 64 |
| Aggregate header names and values | 32 KiB UTF-8 |
| Concurrent HTTP calls | 64 |
| Pending plus active sessions | 32 |
| Session idle age | 15 minutes |
| Session sweep interval | 60 seconds |
| Optional GET SSE heartbeat | 15 seconds |
| Capacity-pressure policy | Oldest inactive session with a disconnected observed SSE stream only |
| CIO connection idle timeout | 180 seconds |
| Session cleanup wait during stop | 2 seconds |

Duplicate `Mcp-Session-Id`, ambiguous framing (`Content-Length` plus `Transfer-Encoding`), duplicate or malformed
`Content-Length`, and oversized chunked bodies fail before dispatch. The optional GET event stream emits only an SSE
comment every 15 seconds, allowing a closed peer to release its concurrent HTTP slot without creating an MCP message;
DELETE, eviction, and server shutdown also cancel its registered handler immediately. Disconnect still does not itself
delete the stateful session. The session remains subject to the separate 32-session and idle-lifetime bounds, but it is
a lower-priority capacity candidate after its observed stream has disconnected.

The 180-second CIO value is an idle connection limit, not a total tool-execution deadline. A separate receive-pipeline
wall-clock timeout was not added because Ktor can pre-buffer the body before that interceptor; the byte cap remains
authoritative and slow chunks are covered by the engine idle policy.

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

Eligible newest-first Proxy and Organizer searches with no content predicate can consume recent, already-warm index
records as branch-prediction hints. Search validates the current size and at most 16 anchors per warm source, but never
performs a cold index build. A hint may only choose a likely rejecting field; that field and the numeric
Proxy/Organizer ID are re-read from the current record before it is skipped. A stale prediction, source
reorder/replacement, query-only path match, unavailable slot, expired or contended cache, unindexed range, Site Map
source, or unsupported search shape falls back to the unchanged raw matcher. Selected summaries are always built from
the current source item, and a final project/generation check triggers at most one full raw retry after explicit
invalidation. The existing raw
source snapshots, 10,000-record scan count, signed cursor payload/version, result order, and 32 MiB content accounting
remain authoritative.

## Bounded WebSocket search

`search_websocket_messages` copies one Montoya WebSocket history list per call and advances a raw source index inside an
HMAC-signed project/query/snapshot cursor. It applies connection ID, direction, and listener-port predicates before
payload length or pattern access. Each page returns at most 50 summaries and scans at most 10,000 raw records. Safe-regex
calls account original plus edited payload lengths against the 32 MiB budget; individually oversized records are
skipped without invoking the regex matcher, and an aggregate-budget stop leaves the cursor at the uninspected record.

The cursor stores only bounded query metadata, the original source size, next index, and one-way first/last boundary
anchors. Appended messages remain outside the original size. Source shrinkage or boundary replacement/reordering fails
with `stale_cursor`; selected summaries are discarded if the Burp project changes after source access or content
materialization. The cursor secret is process-local, so server restart invalidation avoids retaining another long-lived
credential. These properties are covered by synthetic/mock regression tests and are not Burp product latency claims.

## Body-free HTTP metadata index

`summarize_http_attack_surface` uses an extension-lifetime index rather than retaining an MCP-session snapshot. Each
requested Proxy, Site Map, or Organizer cache stores only the newest 5,000 metadata slots: source/index and bounded
stable source ID where available, a one-way metadata fingerprint, scheme, host, port, method, a query-free path capped
at 512 characters, status, MIME classification, Proxy timestamp, response presence, and scope classification. It retains
no message body, header or note values, complete URL, or Montoya object. The three-source worst-case entry count is therefore
15,000, independent of Burp history size; omitted and unavailable counts are explicit.

A refresh still requests the selected Montoya source list, because the current API has no native metadata cursor. For a
warm same-size source, up to 16 evenly distributed metadata-only anchors are re-read. Valid append-only growth reuses
retained slots and extracts only new entries while dropping old slots above the cap. A size decrease, sampled-anchor
change, project change, explicit Scope/project-option mutation, or 30-second maximum reuse age forces a rebuild. A
project transition clears all source entries before mismatch or current-project output is returned. This is conservative
cache freshness, not a claim that Montoya provides a complete same-size mutation event stream.

A synthetic 100,000-record list regression verifies that a cold source build dereferences no more than the 5,000
retained records plus 16 anchors; it does not treat that synthetic test as a Burp latency or allocation benchmark.
Search's hint-only path reads only the current source list and at most 16 anchor records per warm source while acquiring
a recent warm snapshot. It uses a non-blocking lock attempt so a concurrent index build cannot add latency to the raw
fallback; every predicted rejection is then independently checked on the current source record.

A separate one-off Java 21 probe used lightweight dynamic Montoya-interface fixtures, a 100,000-record Proxy list, the
5,000-record retained range, three warm-up rounds, and twelve measured rounds. Its aggregation case deliberately used
5,000 distinct services and path prefixes, which is a bounded allocation stress case rather than a typical project.
Both comparison runs used the same JFR allocation-profiling configuration:

| JFR probe path | Before median | Current median | Weighted allocation samples on relevant stacks |
|---|---:|---:|---:|
| Cold 5,000-record index rebuild | 26.298 ms | 14.827 ms | 105.86 MiB → 41.45 MiB |
| Warm 5,000-key attack-surface aggregate | 11.937 ms | 5.001 ms | 60.93 MiB → 9.40 MiB |

Weighted JFR samples are estimates, not exact retained-heap measurements, and include allocation noise from the dynamic
interface fixture. Across the complete probe, allocation-sample events fell from 1,389 to 668 and young collections
from four to two. The index reuses one closeable SHA-256 instance,
uses typed fingerprint framing and shared normalized MIME names, and avoids copying already-safe query-free paths. The
aggregate first computes exact key counts and then allocates detailed counters only for the at most 100 returned
services and 200 returned paths. Allocation-free ASCII classifiers replace per-segment regex matchers, and path-prefix
construction scans only the requested one to four segments. These figures are local regression evidence, not Burp
Suite latency claims; an actual large-history Burp JFR/soak run remains required.

A second one-off Java 21/JFR probe exercised metadata search over a synthetic 100,000-record Proxy list with concrete
primitive source-ID and host methods. The selected host occurred at the 5,000th newest position, the index was already
warm, and each phase contained 120 measured calls. Every cached rejection still read the current numeric ID and the
same `httpService().host()` field as the raw matcher. Under JFR, raw and indexed median call times were 0.537 ms and
0.437 ms, while weighted allocation samples inside the marked phases were 28.47 MiB and 13.87 MiB. Three separate
no-build-cache runs without JFR measured raw medians of 0.532/0.501/0.527 ms and indexed medians of
0.298/0.336/0.289 ms. Full request and response dereferences for a representative call fell from 5,000 each to 17 each
(the selected record plus 16 anchors). The indexed call made 5,016 service, 5,017 host, and 5,018 numeric-ID reads to
preserve anchor, identity, and current-field validation.
These sub-millisecond figures remain sensitive to fixture, JIT, and recorder noise. The probe is allocation/accessor
regression evidence, not a Burp latency claim. A cold search does not build the index and keeps the
original raw path.

The attack-surface tool defaults to in-scope Proxy metadata, strips query strings, normalizes likely numeric, UUID, hex,
and long token path segments, and bounds service/path/global method, status, MIME, and file-extension count lists.
Each snapshot captures a monotonic invalidation generation. The tool rechecks both that generation and the current
project after aggregation, performs at most one bounded rebuild if an explicit invalidation won the race, and fails
closed if state keeps changing. MCP Scope and project-option mutations mark the index unavailable and invalidate it
both before and after the mutation; non-cancellable cleanup releases that barrier even if the tool call is cancelled.
External Burp UI changes remain subject to the documented anchors and 30-second reuse limit because Montoya exposes no
corresponding lifecycle event.

Individual detail and action tools do not trust aggregate cache entries: their existing resolvers fetch the current
Burp object and validate the project and stable or opaque Site Map identity immediately before use. Search likewise
uses cache entries only as advisory field-selection hints and builds every returned reference from the current source
item.

## Stable-ID lookup and action hot paths

The unified HTTP reader uses Montoya's filtered overloads for Proxy and Organizer references; the WebSocket reader does
the same. Montoya may still inspect its internal store, but the extension no longer asks it to construct and return a
complete list before selecting one record. Site Map keeps positional validation because its opaque ID deliberately
fails closed after removal or reorder and Montoya exposes no direct stable-ID lookup. The HTTP reader rechecks the
project after materializing a bounded result and drops that result if a project transition won the race.

Stable-ID request actions cap source and resulting requests at 2 MiB. Exact replay computes byte length from
`bodyOffset + body.length` and does not materialize a complete byte array. Request text is held behind a non-thread-safe
lazy value scoped to the invocation: when action approval is disabled,
or HTTP approval is disabled/auto-approved, the potentially large string is never created. Parameter replacements are
resolved once per affected parameter type and applied as at most one removal plus one addition, rather than reparsing and
rebuilding the immutable request for every mutation. Response previews slice the Montoya byte array before text/base64
conversion and are capped at 64 KiB. A 100 ms–120 s Montoya response timeout bounds response reading without wrapping
an ambiguously delivered request in an unsafe coroutine retry.

Intruder semantic selectors resolve at most 32 non-overlapping parameter/header/body ranges before approval and build one
native request template. Replay recording searches at most the last 10,000 Site Map entries for the newly added response;
a missing stable reference becomes a non-retryable warning after the request has completed.

The unified raw path normalizes HTTP/1.1 request preludes in one pass instead of up to five complete replacement passes.
Bodies remain untouched, and HTTP/2 header construction reuses its ordered map rather than allocating a second merged
map. The parsed auto-approval target list is also reused until the persisted raw value changes.

Each raw call accepts one nested protocol variant, computes request size from `bodyOffset + body.length`, and returns
structured state. Network sends use an explicit HTTP mode, `RedirectionMode.NEVER`, a 100 ms–120 s timeout, and
a body preview capped at 64 KiB. A post-delivery exception is `execution_uncertain`, preventing an unsafe model retry.
Raw routing executes one approved destination and retains fixed destination audit kinds; HTTP/2-to-Intruder is rejected
before approval or request construction until a supported Burp runtime is verified.

A standalone Java 21 `ThreadMXBean` probe compared the previous replacement/substrings pipeline with the current
compiled `normalizeHttpContent` implementation. After warm-up, the median of nine alternating rounds was:

| Input | Previous median / allocation | One-pass median / allocation | Allocation reduction |
|---|---:|---:|---:|
| 1 MiB body after a 3 KiB escaped prelude | 1.65 ms / 3,165,616 B | 1.57 ms / 2,103,648 B | 33.5% |
| 256 KiB escaped prelude, no body | 0.98 ms / 1,039,736 B | 1.00 ms / 494,064 B | 52.5% |

Latency is effectively neutral for the header-only synthetic case and about 5% lower for the large-body case; the
reliable gain is fewer temporary strings and substantially lower allocation. Both paths produced identical output,
including byte-for-byte preservation of body text.

## Diagnostics and audit overhead

Runtime diagnostics use atomic counters and timestamps on the HTTP admission and session-registry paths. They retain no
request metadata, client names, headers, bodies, or Montoya objects. The Swing diagnostics view samples one immutable
snapshot per second, so it does not poll Burp history or session transports.

The audit path constructs one small record at tool completion. Argument keys are capped at 16, approvals at 8, and all
stored fields are ASCII/value-free; raw arguments, outputs, exception messages, and traffic are never serialized.
Consolidated routing, configuration, and global-control tools retain only fixed approval classifications such as
`request_routing:intruder`, never the operation argument value. The
in-memory deque holds 50–1,000 records (250 by default) for at most 30 days, the persisted JSON document is capped at 1 MiB, and copied
JSONL is capped at 100 records/64 KiB. A single daemon writer coalesces completions for 250 ms, keeps persistence off
request workers and the Swing event thread, and flushes synchronously only during explicit test/lifecycle barriers.

## Reproducible packaging

The extension manifest previously included build time, user, JDK, and Gradle fields, and `embedProxyJar` mutated the
completed Shadow JAR through the platform `jar` command. Both paths introduced timestamps outside Gradle's reproducible
archive controls. The proxy and extension now disable file timestamps, use reproducible entry ordering, add the nested
proxy as a normal Shadow input, and stream-verify the source and embedded SHA-256. Incremental Kotlin compilation is
disabled because clean and incremental compilation can emit different debug line tables for the same source. A clean
build and a forced rerun from identical inputs must produce byte-identical proxy and extension JARs.

## Deferred changes that affect behavior or APIs

The feature phase added compact stable-ID summaries, bounded field reads, signed HTTP/WebSocket cursors, complete-record
Scanner compatibility pagination, and a constrained regex policy. Remaining performance work is deliberately narrower:

1. Add hard timeouts to remaining long-running read/config tools only where they can work with Ktor receive behavior and
   without treating an ambiguous mutation as retryable.
2. Add lifecycle event hooks only where Montoya freshness is provable; selected detail/action records must still be
   resolved and identity-checked against the current source.
3. Evaluate a streaming structured-output encoder if future result types approach the current page-level character cap.

## Regression checks

Performance changes should preserve the following:

- Only selected page items invoke serialization.
- Unified search never exceeds its result, metadata-scan, content-scan, cursor, URL, or note bounds.
- Metadata-rejected search records never consume content budget or invoke body scans.
- The metadata index retains no bodies, headers, notes, complete URLs, or Montoya objects; source/project/output bounds and
  cache freshness state remain explicit.
- Attack-surface results revalidate project and generation after aggregation, retry at most once after invalidation, and
  cannot build or return a snapshot during an MCP Scope or project-option mutation.
- Stable-ID Proxy/WebSocket/Organizer readers use filtered lookup APIs instead of full returned snapshots.
- Derived request actions render full request text only when an interactive approval needs it.
- Signed HTTP, WebSocket, and Scanner-issue cursors reject tampering, project changes, and stale source boundaries.
- HTTP comparison never inspects more than 1 MiB per reference and never claims equality for a truncated matching prefix.
- Focused active audits reject out-of-scope requests and missing/overlapping insertion points before Scanner starts.
- Scanner get/cancel accepts only extension-owned task IDs; at most eight active and 32 retained handles are tracked.
- Collaborator waits, result counts, scan windows, per-field details, and total detail bytes remain bounded.
- Approval cancellation remains a coroutine cancellation rather than a tool error.
- Server stop/restart closes pending and active SDK transports exactly once and waits no more than two seconds.
- HTTP body, URI, header, call, session, idle, and shutdown limits remain enforced before or around SDK dispatch.
- Proxy graceful shutdown sends DELETE when a session exists, but never blocks shutdown for more than two seconds.
- Proxy request concurrency and pending queues remain bounded under bursts; rejected requests are never forwarded.
- Ambiguous post-send failures never retry arbitrary or custom requests.
- Existing proxy extraction is skipped without reading the nested JAR.
- Repeated builds from identical inputs produce byte-identical proxy and extension JARs.
- Bounded list output contains only complete records and reports truncation explicitly rather than emitting invalid JSON.
