# reburp feature and architecture selection

## Latest configuration and audit follow-up

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
