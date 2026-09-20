# Configuration-boundary architecture review (unreleased)

Reviewed baseline: `c9bb55decf52974530cbe8448acdee159a731afe` (`4.12.0-rc.5`).
This is a focused source and local-test review, not a complete security audit or release approval.

## Assessment

The existing composition is sound: `ExtensionBase` owns extension lifetime, `KtorServerManager` serializes listener
lifecycle, `ToolServices` retains service state across listener restarts, and tools/resources share execution, audit,
and session-approval wrappers. The full suite checks the exact 24 Community / 38 Professional tool catalogs, schema
fingerprints, annotations, edition gates, native HTTP, and the embedded stdio proxy. No catalog or tool behavior changes
are needed for the fixes below.

## Fixed configuration boundaries

| Finding | Change | Regression coverage |
| --- | --- | --- |
| UI/client port bounds were not enforced on persisted listener-start settings. Port zero could request an ephemeral listener inconsistent with the advertised endpoint. | Introduce the credential-free `config/McpEndpoint` value. Listener startup, previews, installation, and Doctor share the UI's numeric-loopback and 1024–65535 policy and canonical URL. Reject invalid startup before catalog registration, credential access, or listener creation. | Endpoint boundary/IPv6 tests; invalid persisted-port and zero-port lifecycle tests. |
| Claude installation performed proxy/config-file work before validating the supplied endpoint, and did not independently validate bearer format. | Validate endpoint and bearer before file work, preserving redacted errors and the existing backup/write path. | Invalid host, port, and credential inputs touch neither the proxy manager nor logging. |
| Client-file reads checked file size and then used an unbounded `Files.readString`; a prior size observation cannot bound a later read. | Extract `providers/ClientConfigFile`. Check regular-file and symlink policy, inspect size on the opened channel, and cap actual reads at 4 MiB plus one overflow-detection byte. Keep strict UTF-8 decoding. | Exact byte boundary, growing stream, malformed UTF-8, oversized file preservation, directory, and symlink tests. |

The UI now reuses the same validated endpoint snapshot for provider installation rather than separately normalizing
host/port. Endpoint validation is in the configuration layer, not the provider layer, so server startup does not depend
on client integration code. No new dependencies or changes to dependency locks, proxy bytes, release gates, approvals,
network actions, tool descriptions, schemas, or result-error compatibility were introduced.

## Local verification

The baseline suite passed 1,008 tests. The updated suite passes **1,021 tests**, with zero failures, errors, or skips.
Two new validation-order regressions were observed failing against the original production code before their fixes.

```bash
./gradlew clean test embedProxyJar generateSbom --no-build-cache
bash scripts/test-release-version.sh
```

Tests include the real loopback CIO lifecycle and packaged stdio-proxy fixtures; they do not drive a real Burp instance.
Packaging verifies the embedded proxy and legal bundle and generates the CycloneDX SBOM. Outputs are development
artifacts under `build/`, not a tagged release or an uploaded CI distribution.

## Retained limitations and follow-up

- `KtorServerManager.kt` still contains endpoint wiring, project-epoch alignment, session registry, and listener ownership.
  These are candidates for a later behavior-preserving file split; broad transport rewrites are not justified by this
  focused configuration fix.
- Retained structured denials can have `isError=false`. Clients must inspect status and retry/side-effect fields. A blanket
  error-flag change would break the pinned compatibility contract and requires separate review.
- The file checks do not implement a filesystem transaction against hostile concurrent parent-directory replacement,
  nor a cross-process lock for simultaneous client configuration writers.
- Real Community/Professional Burp startup, UI installation, and external-client tests remain required. Local mocks and
  protocol fixtures do not prove those integrations work.
- Signed source, fresh candidate vulnerability/conformance evidence, independent reproducibility, and exact-byte Burp
  smoke/publication gates in [RELEASING.md](RELEASING.md) remain mandatory. No version/tag/asset was published by this review.
