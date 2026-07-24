# v5 sessionless approval model

- **Status:** Stage A design baseline; not implemented in the production endpoint
- **Decision date:** 2026-07-24

This document defines the security baseline for approvals if Burp MCP adopts a modern, per-request MCP revision. It does
not change the v4 production endpoint. The current `2025-11-25` implementation remains stateful and keeps its existing
bounded session grants until a separately validated v5 migration.

## Why v4 approval state cannot be copied into v5

The v4 endpoint attaches a fixed, value-free approval enum set to an active MCP protocol session. A call sees the grants
that existed when that invocation started plus any grant it receives itself. DELETE, idle or pressure eviction, listener
restart, and Burp shutdown remove the state.

The proposed modern protocol has no protocol sessions and explicitly forbids treating an HTTP connection or stdio
process as a conversation boundary. Its per-request `clientInfo` is self-reported. Therefore none of the following is a
safe replacement for a v4 session key:

- a TCP connection, HTTP keep-alive pool, response stream, or stdio process;
- source address or port;
- self-reported client name, version, capabilities, task, thread, or conversation metadata;
- bearer-token value or a hash that would turn one installation credential into a global approval grant;
- an MCP request ID, which is client-selected and has only one-request correlation semantics.

Connection-scoped approval must not silently become installation-wide approval during migration.

## Initial v5 policy

The first modern v5 candidate will use the following fail-safe policy:

1. **No transient cross-request grants.** Modern requests do not expose **Allow for This Session**. Each protected
   operation is approved independently unless an existing explicit persistent policy applies.
2. **Persistent policies remain user decisions.** Host and host:port outbound policies, source-specific project-data
   policies, request-routing policy, and Scope policy may still be selected explicitly in Burp. They retain their current
   reset controls and never derive from client metadata.
3. **Always-explicit actions remain always explicit.** Scanner starts, sensitive configuration operations, task-engine
   changes, Proxy Intercept changes, and other operations that currently offer only **Allow Once** continue to do so.
4. **Authentication is not authorization.** The per-installation bearer authenticates access to the loopback endpoint;
   possession of it does not imply approval for traffic, project data, or mutation.
5. **Every request revalidates authority.** Stable ID, current project, source, target, Scope, and policy checks run on
   each request and again at the existing pre-materialization or pre-side-effect boundaries.
6. **Ambiguous work is never retried automatically.** Cancellation or transport loss after a side effect may have begun
   produces an uncertain result or local reconciliation requirement, not an automatic second execution.

This policy intentionally trades some convenience for a migration that cannot broaden authority accidentally.

## Request cancellation and approval dialogs

A modern HTTP SSE response stream is scoped to one request. Closing it must cancel that request coroutine when the
released SDK exposes the lifecycle. Stdio cancellation must use the matching request ID supplied by the SDK.

For both transports:

- cancellation before a decision disposes the pending Swing dialog and creates no approval or side effect;
- a dialog result is valid only for the invocation that displayed it;
- cancellation after authorization but before execution rechecks coroutine activity before entering Burp work;
- cancellation after a side effect starts must preserve `uncertain` semantics where completion cannot be proved;
- ordinary notification or audit failures do not change an approval decision;
- cancellation exceptions are never converted into approval denial, generic Burp failure, or successful completion.

The current serialized Swing approval gate remains the UI authority unless a later Montoya API supplies a safer native
primitive.

## Project transitions, subscriptions, and tasks

Project or source continuity must be explicit rather than inferred from a connection:

- a resource read repeats its current-project and stable-ID checks every time;
- a subscription is bound internally to the project generation observed when its listen request starts;
- project transition closes stale subscription delivery before any new-project notification can be emitted;
- a long-running task uses a random extension-owned identifier and remains project-bound without storing traffic,
  targets, credentials, or client-provided values in the task registry;
- task lookup and cancellation repeat the project binding check;
- no subscription or task identifier acts as an approval grant.

## Future approval handles

The initial v5 candidate will not add approval handles. If repeated per-operation prompts prove unusable, handles require
separate review and all of these properties:

- generated by `SecureRandom`, opaque, and compared without exposing the raw value in logs or diagnostics;
- bounded in count, short-lived, revocable, and operation-class-specific;
- one-time where replay could authorize a side effect;
- stored only in memory and cleared on listener restart, project transition, reset, and Burp shutdown;
- never keyed by or transferable through self-reported client identity;
- never contain a target, URL, project ID, traffic, header/body value, credential, local path, or client-provided value;
- never upgrade a connection grant into a persistent policy.

Modern MRTR `requestState` is attacker-controlled when it returns from a client. It must not become authorization merely
because it is opaque. If it is ever used for approval flow, its integrity, expiry, request binding, replay rules, and
bounded server-side consumption must be proven independently. Burp-local Swing approval does not require MRTR for the
initial candidate.

## Audit and diagnostics

Modern mode keeps fixed-cardinality, value-redacted observability:

- audit records classify the operation and decision but exclude credentials, traffic values, project IDs, paths, raw
  exceptions, and client identity;
- request correlation is bounded and one-way and is not an authorization key;
- diagnostics may count per-operation approvals, denials, cancellations, and expired handles if handles are later
  approved, but do not retain handle or request values;
- negotiated protocol counters remain bounded and do not partition by client name.

## Acceptance criteria for a private v5 candidate

The approval gate is not complete until automated and live tests prove all of the following:

1. Reusing a TCP connection, HTTP client, stdio process, client name, or request metadata cannot reuse an **Allow Once**.
2. Concurrent requests cannot observe another invocation's decision.
3. Modern dialogs contain no session-grant option; v4 dialogs and grants remain unchanged on the compatibility line.
4. Explicit persistent policies still work, remain source/operation-specific, and return to prompt-by-default after reset.
5. Cancellation while a dialog is open closes it and records no grant or side effect.
6. Project transition invalidates stale task and subscription state before any protected data is returned.
7. Unknown, expired, replayed, malformed, or wrong-operation handles fail closed if handles are ever introduced.
8. Listener restart and Burp shutdown leave no transient approval state.
9. Audit and diagnostics remain bounded and contain none of the prohibited values above.
10. Community and Professional release-candidate bytes pass the same behavior in supported clients.

## Deferred decisions

The following remain open until stable protocol, SDK, conformance, and client evidence exists:

- whether one binary supports both protocol eras or v4 remains a separate compatibility line;
- whether any supported client needs MRTR-based approval interaction;
- whether a bounded approval handle is necessary at all;
- whether a future authenticated multi-user mode requires a principal model. Remote listeners remain unsupported.
