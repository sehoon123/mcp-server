# Pinned CI Node tools

CI installs the two MCP conformance versions and the Ajv CycloneDX schema validator from `package-lock.json` with
`npm ci --ignore-scripts`. The aliases allow
the stable and modern-protocol baselines to coexist without `npx` downloading moving transitive dependencies.

The 2026-09-14 maintenance refresh updates only the locked transitive `fast-uri` (3.1.5 → 3.1.7), `hono`
(4.12.34 → 4.13.7), and `qs` (6.15.3 → 6.16.0) packages. Direct conformance/Ajv pins and the production protocol
contract are unchanged. A fresh dev-inclusive, lock-only `npm audit` returned zero findings after the update; that
point-in-time local result is not immutable release evidence.

The 2026-10-29 maintenance refresh follows a fresh CI audit with 5 moderate, 4 high, and 1 critical affected package
nodes. It updates 11 existing transitive lock entries: `@hono/node-server` 2.1.5, `@modelcontextprotocol/sdk` 1.32.2,
`body-parser` 2.4.0, its nested `content-type` 2.1.0, `fast-uri` 3.1.9, `hono` 4.13.14, `ip-address` 10.7.5,
`proxy-addr` 2.0.8, `qs` 6.17.1, `undici` 7.30.1, and `zod` 4.6.7. The SDK's declared adapter range permits
`^1.19.9 || ^2.0.5`; the fixed 2.x adapter requires Node >=20, satisfied by CI's Node 22. No package is added/removed,
no direct pin changes, and no audit exception is added. A fresh dev-inclusive lock-only audit returned zero findings
and passed the existing fail-closed validator. These are point-in-time development results, not release evidence.

CI uses only the conformance **client** on Ubuntu against a numeric loopback endpoint. Ajv runs with its `$data`
extension disabled against generated, size-bounded release output. These Node packages are not shipped in the JAR.
The release gate still rejects high, critical, malformed, or unreviewed findings; the historical, exactly pinned
`GHSA-frvp-7c67-39w9` Hono-adapter/SDK exception is unchanged and was not used by this zero-finding result. Fresh
candidate audits remain mandatory.
