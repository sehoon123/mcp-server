# Project-bound list changes and resource subscriptions

- **Status:** Stage A design complete; wire subscriptions remain disabled
- **Decision date:** 2026-07-24
- **Production protocol/SDK:** MCP `2025-11-25`, Kotlin SDK `0.14.0`

## Decision

The v4 endpoint continues to advertise `tools.listChanged=false`, `resources.listChanged=false`,
`resources.subscribe=false`, and `prompts.listChanged=false`.

This is deliberate rather than a missing capability:

- the tool, fixed-resource, template, and prompt catalogs are immutable for one listener lifetime;
- Burp edition is read while the listener catalog is built, and a listener restart already closes every MCP session;
- configuration changes alter authorization or behavior, not the advertised names or schemas; and
- the released SDK does not provide a bounded, project-aware resource-subscription lifecycle that this extension can
  safely enable.

A client must reconnect and rediscover after a listener restart. The server does not send a list-change notification when
no list changed.

## Kotlin SDK `0.14.0` findings

The released server SDK owns stable-protocol subscription state internally. Its `resources/subscribe` handler accepts the
request URI directly into a per-session persistent map without checking that the URI is a registered concrete resource
and without a per-session subscription limit. The notification service defaults to an unbounded event buffer. It exposes
no public hook for this server to validate a subscription against the current Burp project generation or to clear only
stale subscriptions; closing the SDK session is the available cleanup boundary.

The same resource registry drives both list-change and resource-update listeners. Replacing a concrete resource to signal
an update can therefore also emit a list-change event. Enabling these flags and trying to repair admission in Ktor would
require a second raw JSON-RPC parsing/dispatch path beside the SDK. That is outside the approved architecture and would
not be a safe compatibility fix.

## v4 project boundary

Unreleased v4 hardening now treats a detected Burp project transition as a session reset boundary:

1. authenticated non-OPTIONS MCP requests compare a fixed-size SHA-256 digest of the current opaque project ID;
2. the raw project ID is not retained in session state, diagnostics, or audit;
3. when the digest changes, all pending and active sessions are detached, event streams are cancelled, memory-only
   approvals are cleared, and transport cleanup is attempted within the existing two-second shutdown bound;
4. a late initialization callback from a detached session cannot reactivate it; and
5. a request carrying an old session ID cannot reacquire the detached session, while fresh initialization can bind to
   the current project.

This request-bound guard complements, but does not replace, the project and stable-ID checks performed by every tool and
resource read. It does not undo an already dispatched Burp operation; cancellation and uncertainty continue to follow the
operation outcome policy. Montoya `2026.7` does not expose a complete project-lifecycle event, so v4 does not claim
immediate asynchronous detection while no MCP request is being admitted. Because wire subscriptions remain disabled, an
idle event stream has no project-data update channel to leak through. A future subscription implementation needs an
authoritative lifecycle signal or a separately reviewed bounded observer before enabling delivery.

## Requirements before enablement

Resource subscriptions or list-change notifications remain **NO-GO** until all of these are true:

1. the released SDK validates subscription URIs and enforces reviewed per-session and listener-wide bounds, or an
   independently approved transport architecture provides equivalent behavior;
2. each subscription stores only a project generation and approved fixed resource class, not a project ID, traffic,
   target, credential, or client-provided identity;
3. project transition closes the old delivery stream and clears its queue before any new-generation event can be emitted;
4. disconnect, cancellation, listener restart, Burp shutdown, and delivery failure deterministically release state;
5. event queues are bounded and duplicate changes are coalesced without changing Burp operations on delivery failure;
6. subscription and notification diagnostics remain fixed-cardinality and contain no URI or client value;
7. list-change events correspond to an actual catalog change; policy changes use a separately defined policy signal rather
   than pretending that tool/resource names changed; and
8. native HTTP, the embedded stdio proxy, and the supported-client matrix pass reconnect, rediscovery, transition, and
   stale-delivery tests.

The proposed modern protocol replaces stable `resources/subscribe` with a long-lived `subscriptions/listen` response.
That does not waive these requirements. The listen request must be bound to its request coroutine and project generation,
and closing it must cancel and discard delivery state before a later request can observe another project.
