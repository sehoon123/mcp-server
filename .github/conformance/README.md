# Pinned CI Node tools

CI installs the two MCP conformance versions and the Ajv CycloneDX schema validator from `package-lock.json` with
`npm ci --ignore-scripts`. The aliases allow
the stable and modern-protocol baselines to coexist without `npx` downloading moving transitive dependencies.

The 2026-09-14 maintenance refresh updates only the locked transitive `fast-uri` (3.1.5 → 3.1.7), `hono`
(4.12.34 → 4.13.7), and `qs` (6.15.3 → 6.16.0) packages. Direct conformance/Ajv pins and the production protocol
contract are unchanged. A fresh dev-inclusive, lock-only `npm audit` returned zero findings after the update; that
point-in-time local result is not immutable release evidence.

CI uses only the conformance **client** on Ubuntu against a numeric loopback endpoint. Ajv runs with its `$data`
extension disabled against generated, size-bounded release output. These Node packages are not shipped in the JAR.
The release gate still rejects high, critical, malformed, or unreviewed findings; the historical, exactly pinned
`GHSA-frvp-7c67-39w9` Hono-adapter/SDK exception is unchanged and was not used by this zero-finding result. Fresh
candidate audits remain mandatory.
