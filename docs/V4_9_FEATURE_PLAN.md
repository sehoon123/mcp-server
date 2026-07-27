# v4.9.0 feature plan — Analysis and reusable workflows

## Objective

v4.9.0 is a feature release. It adds one passive analysis family, reusable project-scoped workflow presets, and a
planning-only Repeater prompt. It does not add client setup UI, multi-instance UX, security-policy profiles, or release
hardening work.

Development takes place on `feature/v4.9-workflow-features`. The v4.8 release tags and draft assets remain immutable.
The v4.9 release candidate is cut only after the implementation and compatibility gates below pass.

## Feature 1 — HTTP session-security analyzer

Add the edition-neutral `analyze_http_session_security` tool.

- Input: the current `projectId` and 1–32 distinct ordered stable HTTP references from Proxy, Site Map, or Organizer.
- Output: per-message authentication/session signals, response-cookie attributes, heuristic login/logout/refresh roles,
  redirect relationships, cross-message cookie observations, and known invariant/variant attributes.
- Cookie names may be returned for correlation; cookie values, authorization values, redirect targets, Domain/Path
  values, expiry values, request/response bodies, and complete raw messages are never returned.
- The selected reference order is treated as a proposed flow, not proof of chronology or causality.
- The tool reports observations and evidence limits, not vulnerability severity or proof of browser behavior.

Implementation reuses `HttpMessageResolver.resolveAll` so source approval, project binding, stable IDs, and one-time batch
resolution match existing HTTP tools. Analyzer materialization is body-free and never reads authentication values. Preserving
the v4.8 Site Map stable-ID/URI contract means Site Map reference verification can privately inspect the existing bounded
identity body samples and header values before analysis; identity material is never returned. Cookie and redirect Location
values are privately inspected only within explicit bounds for fixed value-free classifications. Header, cookie, and
selected-character work is explicitly bounded.

## Feature 2 — saved workflow presets

Add four edition-neutral tools:

- `save_workflow_preset`
- `list_workflow_presets`
- `delete_workflow_preset`
- `execute_workflow_preset`

Presets are stored in Burp project-backed `extensionData()` with a versioned JSON envelope. v1 supports:

1. HTTP metadata search settings;
2. WebSocket metadata search settings;
3. HTTP comparison settings.

A preset stores reusable settings only. It never stores a project ID, cursor, stable reference, traffic/result content,
request/response body, credential, token, HTTP content predicate, WebSocket payload regex, or WebSocket connection ID.
Search limits/cursors and comparison references are supplied only at execution time. Execution delegates to the existing
search/comparison services so their approvals, progress, cursor, and result behavior remain authoritative.

Limits: 64 presets per project, 256 KiB serialized envelope, case-insensitive unique names, deterministic listing, and
fail-closed preservation of malformed or unknown-version data. v4.9 exposes preset management through MCP tools; a new
native preset-management UI is not part of this milestone.

## Feature 3 — planning-only Repeater prompt

Add the edition-neutral `plan_repeater_tests_without_sending` prompt.

- Required argument: one canonical `burp://http/...` reference.
- Optional argument: bounded planning focus.
- Result: observed baseline, evidence limits, and at most eight prioritized one-variable-at-a-time manual tests.
- Prompt retrieval reads no Burp data.
- The generated instructions prohibit sending/replaying, routing or creating a Repeater tab, Scanner execution, editor
  writes, and every mutation tool. Execution requires a later explicit user action in Burp Repeater.

The prompt uses the existing canonical reference and focus validators. Supported-client validation must confirm that
normal and adversarial focus text does not cause automatic routing, sending, or mutation before release.

## Delivery sequence

1. Add the Repeater prompt and exact prompt-catalog/transport tests.
2. Implement the pure bounded session analyzer, then wire it through batch resolution and common tool registration.
3. Implement safe preset models/store, CRUD tools, then delegated execution.
4. Update exact Community/Professional catalogs, schemas, docs, and compatibility notes once all three slices are green.
5. Run focused tests after each slice, then the full JDK 21 suite, reproducible JAR/SBOM builds, Community/Professional
   smoke, and supported-client prompt validation.

## Public compatibility

The change is additive. Existing v4 tool, resource, prompt, approval, transport, and URI contracts remain unchanged.
Community/Professional catalogs move from 19/26 to 24/31 tools and from 3/4 to 4/5 prompts. Clients must reconnect and
rediscover capabilities after upgrading. Fixed resources and resource templates remain unchanged.

## Acceptance gates

- Session analyzer handles exactly 32 distinct references, rejects duplicates and 33 references before project, approval,
  or source access, preserves caller order, and produces no network or mutation side effect.
- Adversarial sentinels prove no raw body, authentication, cookie, redirect, scope, or lifetime value appears in analyzer
  output, error, log, or audit text. Analyzer materialization leaves body and authentication-value accessors unused; the
  pre-existing bounded Site Map stable-ID verification described above remains unchanged.
- Presets survive listener restart and project save/reopen semantics, remain isolated to the current project, and never
  persist runtime references/cursors/results or prohibited content.
- Preset execution produces the same delegated input normalization, approvals, progress, cursor behavior, and result as
  the corresponding direct tool.
- Repeater prompt retrieval performs zero traffic reads or mutations; native HTTP and embedded stdio expose identical
  prompt content.
- Exact catalog/schema/annotation tests, full unit/integration tests, reproducibility, SBOM/legal gates, and supported
  Community/Professional/client matrices pass.

## Explicit non-goals

- Client setup/export installers or setup wizard.
- Multi-instance labels, naming, identity, or resource-URI changes.
- Security-policy profiles or settings portability.
- Automatic Repeater tab creation, request generation, routing, sending, Scanner execution, or editor mutation.
- Persisted traffic, credentials, active session grants, approvals, project IDs, stable IDs, or raw request/response data.
- Additional tool families beyond the analyzer and workflow-presets APIs described here.
