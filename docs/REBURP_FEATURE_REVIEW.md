# reburp feature and architecture selection

## Current follow-up — result quality, not API surface (4.12.5 candidate)

Review baseline: bridge `f8c28f8`; ReBurp remains `892e475cf3d74020cdb82cc1c6368187b5e69404` (1.1.15), and Montoya
`2026.7` contracts were checked at `daccdcaafb47025eb9c6c6d61f7700e95059a719`. No upstream extension or target was run.
Independent `openai/gpt-6.1-sol` plan and implementation reviews found no implementation blocker; a requested terminal
project/lifecycle regression was added. This is development review, not release/native validation evidence.

- Isolate optional execution-metadata failures rather than replacing every field with unavailable.
- Use native echoed correlation labels for bounded per-input IDs while preserving original user labels in MCP results.
  Read terminal `DROPPED` labels/statuses because Montoya does not deliver them to the response callback. Never infer
  delivery or absence from allocated IDs, completion order, missing rows, or incomplete native observations.
- Distinguish native-call completion, response presence and preview failure on existing sends. Keep prepared-request
  length distinct from wire provenance, and move the normal no-Site-Map-storage notice to `warning` instead of `error`.
- Keep 24/38 tools, existing approvals/fences/limits, no automatic retry, no raw-result cache and no automatic Site Map
  recording. ReBurp's returned request/response pairing is useful inspiration, not a final-wire identity guarantee.

The new accessor regression failed on the baseline before the fix. Mock/service and MCP wire tests cover the changes;
actual Burp execution/representation and model-task/performance evidence remain **NOT RUN**. The proposed broader
send-result evidence store remains deferred pending retention, approval and project-atomicity design.

## Current follow-up — reference batches and marked issue evidence

Reference: [forefy/reburp 1.1.15 at `892e475cf3d74020cdb82cc1c6368187b5e69404`](https://github.com/forefy/reburp/tree/892e475cf3d74020cdb82cc1c6368187b5e69404),
unchanged when HEAD/latest release were rechecked. Source inspection only: no upstream build, load or target request.

- `UiRoutes.kt:230` / `UiElementRoutes.kt` motivate selection-to-follow-up ergonomics, **not** an upstream bulk-copy
  equivalent or generic UI automation. The bridge extends its own public context menu to copy 2–8 HTTP references.
  It preserves single-item behavior, freezes project binding before queueing, rejects partial results and uses only
  direct native IDs or one bounded object-identity lookup, not sampled-content identity guesses. No new MCP schema/tool.
- `MessageRoutes.kt:770–849` motivates optional raw byte markers on the existing Professional `create_scanner_issue`.
  Flat ranges point into frozen `refs`; they are approved with exact evidence and applied only to new issue copies.
  Upstream character-length range checks and shared-history mutation assumptions are not copied. This does not turn
  reflection offsets into full ranges or decoded-gzip positions into raw evidence coordinates, and proves no finding.
- `HttpRoutes.kt:610–704` motivates only a documented role-labelled evidence recipe using existing comparison/session
  tools and prompt `focus`. No active auth-diff orchestrator, new prompt, credential/role persistence or status/length
  vulnerability verdict is introduced. The actual callable issue tool is `create_scanner_issue`; the earlier research
  phrase `record_scanner_issue_from_ids` was not a callable name.

Native batch-wrapper compatibility, clipboard behavior, and Professional marker rendering/persistence remain **NOT RUN**.
Existing approvals, complete-byte evidence rechecks, project fences, 24/38 tool counts and release gates remain intact.
Native report export and send-result storage/ref association remain deferred for explicit sensitive-export or
retention/project-atomicity design. `find-references` does not justify a new tool beside existing text/regex search.

## Previous follow-up — stored inspection and diagnostic export

Reference: [forefy/reburp 1.1.15 at `892e475cf3d74020cdb82cc1c6368187b5e69404`](https://github.com/forefy/reburp/tree/892e475cf3d74020cdb82cc1c6368187b5e69404).
Source inspection only: the reference extension was not built, loaded or sent target requests.

The next development changes select three ideas without copying upstream implementation or expanding execution rights:

- `HttpRoutes.kt:250–265` motivates passive parameter reflection. The bridge uses one bounded stored-reference selector,
  exact raw request-value bytes, complete counts and first-16 offsets for separate header/body sections. It does not use
  unbounded string splitting, return values/excerpts, decode representations, or label a reflection as XSS.
- `UtilityRoutes.kt:187–200` motivates explicit stored gzip reading. The earlier decompression deferral remains valid
  for generic codecs/stacks. This narrow successor validates a single declared gzip member with input/output caps,
  optional-header and trailer checks using JDK primitives, and fails closed without content on mismatch or limits.
  Native Burp normalization/provenance is still **NOT RUN**; current headers/bytes are validated, not guessed or resubmitted.
- `ActivityLogExport.kt` and `ActivityLogFilter.kt` motivate field-specific literal filters and view-order HTML/CSV export.
  Only the existing redacted six-column metadata table reaches the clipboard; no raw traffic log, filesystem writer,
  report content, credentials, filter text, or additional persistence is introduced.

Existing tools/resources retain approvals, project fencing and read-only semantics; no tool, dependency, network action
or release gate is added/relaxed. See README for exact schemas/caps and DEVELOPMENT for regression/native scenarios.
The request-parameter inventory, stored timing, and global pacing counters from the preceding follow-up remain intact.

Not selected: generic UI click/type automation can operate approval dialogs or send traffic outside reviewed APIs;
internal Swing locator paths are not a stable public Burp contract. Authentication-diff orchestration largely overlaps
existing tools and requires separate bounded multi-send/result-association design. Status/body-length equality is not
proof of authorization bypass, and omitting one header does not establish an unauthenticated request. Existing loaded
artifact SHA-256 diagnostics already cover build identification without nondeterministic build timestamps.

## Previous configuration and audit follow-up

Reference: [forefy/reburp 1.1.7 at `432349394b49ca8fa72fda6cf940796d38e39851`](https://github.com/forefy/reburp/tree/432349394b49ca8fa72fda6cf940796d38e39851).
Source inspection only: reburp was not built, loaded into Burp, or queried against any target.

The projects have different goals. reburp exposes a broad Montoya REST/OpenAPI surface; this bridge offers a compact MCP
catalog with independent authentication, approvals, project fencing, and bounded output. Matching every REST operation
would expand authority and catalog cost without proving safer or better agent behavior.

### Lessons applied or retained

- **Keep recent diagnostics useful under truncation.** reburp's
  [`LogRoutes.kt`](https://github.com/forefy/reburp/blob/432349394b49ca8fa72fda6cf940796d38e39851/src/main/kotlin/com/reburp/routes/LogRoutes.kt)
  defaults to newest-first log pages and reports page counts. Our native audit table already provides recent-first
  sorting and visible counts, but review found that a size-capped JSONL export retained an older prefix and lost the
  newest events. The independent fix retains the newest complete suffix while preserving append order and the existing
  64 KiB limit. Boundary tests cover exact fits, empty/oversized newest records, and no mutation of retained state.
  No raw log content, REST endpoints, or upstream implementation was copied.
- **Check claims mechanically, without confusing coverage with behavior.** reburp's
  [`tools/api_coverage.py`](https://github.com/forefy/reburp/blob/432349394b49ca8fa72fda6cf940796d38e39851/tools/api_coverage.py)
  gates method-name coverage and explicitly describes its limits. We retain the stronger fit for our product: exact
  edition catalogs, schema/annotation fingerprints, output budgets, and native HTTP/stdio contract tests. Do not chase
  a full-API percentage or treat these checks as real Burp smoke evidence.
- **Keep input and output contracts symmetric.** Independently of reburp's implementation, this follow-up bounds client
  configuration serialization as well as reads. A valid compact input can grow beyond 4 MiB after merging or pretty
  printing; bounded UTF-8 streaming now rejects that update before backup/replacement instead of writing a file the next
  installation cannot read. Tests include multibyte text, JSON escaping, pretty-print growth, and exact byte boundaries.

### Not adopted

The referenced reburp [security policy](https://github.com/forefy/reburp/blob/432349394b49ca8fa72fda6cf940796d38e39851/SECURITY.md)
documents unauthenticated loopback access, and its server uses permissive CORS and captures raw call content. We retain
mandatory bearer authentication, strict Host/Origin checks, source/action approvals, redacted metadata-only auditing,
and disabled-by-default code execution. Broad execution, scanning, active WebSocket, raw-log persistence, and generic
administration surfaces are not imported. No dependency or tool catalog change is introduced by this comparison.

See [ARCHITECTURE_REVIEW.md](ARCHITECTURE_REVIEW.md) for verification and retained release limitations.

## Historical feature review — 2026-09-16

Reference: [forefy/reburp at `20b6efb568128e2cb5fdf5b313a14b183f15c7d7`](https://github.com/forefy/reburp/tree/20b6efb568128e2cb5fdf5b313a14b183f15c7d7).
At that review the upstream head was unchanged from RC2. It compared feature groups with MCP source
`24c3b6bf91bc37fc9fd565bb07fd396fd542f445`; it did not establish full Montoya API parity or live behavior verification.

### Selected for `4.12.0-dev.4`

Two opt-in projections extend `get_http_message` without adding tools or execution capabilities:

1. **One header's parsed values:** `headerName` with explicit `request_headers`/`response_headers` avoids transferring
   unrelated headers, body, URL, and notes. It preserves duplicate order and empty values instead of returning only
   the first match. Complete-input/output bounds prevent a truncated sample being reported as missing.
2. **Native response MIME observations:** `part: "response_mime"` returns stated/inferred labels and a nullable
   disagreement, only on demand. Unknown/ambiguous labels are not treated as confirmed agreement or disagreement;
   different labels are not a vulnerability verdict. The existing HTTP resource template supports this part too.

Both use the existing resolver/source approval and final project fence, with cooperative cancellation and sanitized
errors. The narrow branches request no unrelated source metadata; Site Map identity validation retains its existing
bounded private sampling. No stored body/headers/selected values are added to audits or persistence. Public nullable
schemas and text/structured compatibility output remain. See the README for exact limits and examples.

Source inspiration: `routes/MessageRoutes.kt` (`commonOf`, header inspection, and response inspection around lines
309–319 and 465–495). Its complete raw-message materialization, first-value-only header handling, and unconditional
unknown-label comparison are not copied. The bridge independently implements its own bounded stored-reference contract.

### Historical feature-group disposition

| reburp group | Bridge coverage / decision |
|---|---|
| Status, Meta, Docs | Existing diagnostics/project/scope resources, typed tool catalog and prompts; no extension-unload/admin facade. |
| Proxy, Site Map, Organizer, WebSocket | Existing stable-reference search, bounded reads and annotations. Do not add active WebSocket or intercept-rule actions. |
| HTTP, Messages | Existing comparison, stable-reference actions and passive session analysis; add only header selection and MIME observations here. |
| Ranking, JSON, response utilities | Existing native ranking, RFC 6901 field selection, structural JSON comparison, keyword/variation analysis; no generic JSON CRUD aliases. |
| Scope, Config, Match & Replace, Sessions | Existing scope and approval-gated filtered options cover some needs, not complete rule parity. No extra credential/rule management surface. |
| Scanner, Issues, Collaborator | Existing bounded issue/evidence reads, human-reviewed issue reporting and owned lifecycle tools; no crawl, new payload catalog or scan expansion. |
| Repeater, Intruder, Request Engine, Bambda, Shell | Existing RC1 functionality remains; no new automation or execution scope. |
| Engagement | Existing metadata summary/correlation and request-only Decoder routing are partial coverage, not equivalents of all discovery functions. No PoC generation/content discovery. |
| Events and logs | Existing value-free metadata signals and sanitized audit UI; do not copy raw traffic/Authorization/Cookie buffers, persistent call bodies or arbitrary logging. |
| Extension Data and Preferences | Project-scoped presets cover deliberate needs; generic key/value administration is not added. |
| Bytes, numbers, codecs, hashes, JWT | Client standard libraries handle generic transforms. Do not restore removed utility tools just to expose native APIs. |
| Burp AI | Not imported: it adds external transmission, cost and approval concerns. |

### Deliberately deferred

- **Stored-body decompression:** reburp `UtilityRoutes.kt:170–182` decodes arbitrary base64 through native decompression
  and materializes a complete string. That is not bounded stored-body decoding. A separate design must establish
  streaming limits, encoding stacks, raw-versus-decoded offsets, malformed-input behavior and complete JSON semantics.
  Current raw reads are unchanged; no decompression-bomb exposure or new dependency is introduced here.
- **Timeline/subscriptions:** existing bounded metadata signals are not an event archive. Raw traffic retention and
  unbounded subscription buffers are not justified by API coverage; keep the existing notification constraints.
- **Misleadingly passive helpers:** `MessageRoutes.kt` timing sends traffic; `BytesRoutes.kt` inspection writes a temporary
  file. Neither is imported as a read-only operation.
- **Header grades/full API coverage:** header presence is not application security. Name-based API coverage cannot prove
  runtime semantics. Keep catalog, schema, size-budget and behavior checks instead of an exposure-percentage goal.

### Historical verification boundary

The development catalog remains 24 Community / 38 Professional tools with unchanged 132,000/200,000-byte budget gates.
Native MIME inference needs actual Burp confirmation; synchronous native getters have no interruptible deadline or
whole-process allocation guarantee. Mock-based unit/wire checks do not replace operator-led exact-byte testing.

The RC3 pre-tag dependency gate remains blocked. This feature work changes no dependency, lock, proxy pin, vulnerability
policy or protected release workflow, and does not authorize a tag/publication or replacement of prior artifacts.
