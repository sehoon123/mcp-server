# Pinned CI Node tools

CI installs the two MCP conformance versions and the Ajv CycloneDX schema validator from `package-lock.json` with
`npm ci --ignore-scripts`. The aliases allow
the stable and modern-protocol baselines to coexist without `npx` downloading moving transitive dependencies.

As of 2026-07-26, `npm audit` reports the moderate `GHSA-frvp-7c67-39w9` advisory through the pinned conformance
packages' MCP SDK / Hono test-server dependency. CI uses only the conformance **client** on Ubuntu against a numeric
loopback endpoint; it does not invoke Hono's Windows `serve-static` adapter. This build-only, non-shipped exposure is
accepted until the pinned conformance baseline can move without changing the production protocol contract. High or
critical findings remain release blocking. Ajv runs with its `$data` extension disabled against generated, size-bounded
release output and has no advisory in the pinned `8.20.0` version.
