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

## Additional audit and serialization review

The endpoint/read fixes were committed as `149f53c61a8b0f4e09c21b3de03415dc3eb90459` with GitHub's verified signing
service. A follow-up comparison with [reburp 1.1.7](REBURP_FEATURE_REVIEW.md#latest-configuration-and-audit-follow-up)
keeps the different products' authority boundaries intact and adds two narrowly scoped fixes:

- **Recent audit export:** the previous 64 KiB cutoff retained an older prefix of the selected records, dropping the
  newest events. Export now retains the newest complete suffix in append order. Exact-fit lines do not pay for a
  nonexistent trailing newline; an oversized newest record cannot silently substitute older history. No retained
  records are deleted and no traffic values are added. A regression test failed on the original export implementation.
- **Client configuration output:** reading at most 4 MiB was insufficient because merging and pretty printing could
  write a larger file that the next installation could not read. The shared encoder now limits bytes during UTF-8
  streaming, including escaping/indentation, before backup/replacement. It retains the existing JSON formatting and
  unrelated properties. Tests cover exact limits, multibyte data, escaping, and compact-to-pretty expansion.

These changes add no tool, resource, approval bypass, network operation, or dependency. reburp source was inspected
without executing its REST server or importing its raw-logging or unauthenticated-access model.

## Main-only consolidation follow-up

The maintainer requested integration of needed work and retirement of all non-main branches. PR #56's useful
`McpErrorPolicy` and exact status-contract test are ported unchanged onto the current tree; its conflict is resolved by
keeping the newer exhaustive native-status classifier. Existing wire outcomes remain unchanged, while newly added
unlisted outcomes in the retained classifiers default to errors until reviewed. This changes no execution or approval
path. [BRANCH_POLICY.md](BRANCH_POLICY.md) records the distinction between verified development integration and release
approval, plus the evidence-preserving retirement of the separate v4.11 promotion track. Native Burp checks are
explicitly **NOT RUN**; no Burp installation is available in this environment.

## Local verification

The baseline suite passed 1,008 tests, initial endpoint fixes 1,021, and audit/serialization fixes 1,030. The consolidated
clean build passes **1,031 tests**, with zero failures, errors, or skips. The two validation-order regressions and the
recent-export regression were observed failing against their original implementations before their fixes. The four
Python live-harness/smoke/observation/vulnerability contract suites also pass 74 fixture tests; those are not real Burp,
live vulnerability-query, or elapsed-observation evidence.

```bash
./gradlew clean test embedProxyJar generateSbom --no-build-cache
bash scripts/test-release-version.sh
```

A second local `embedProxyJar generateSbom --rerun-tasks --no-build-cache` produced identical JAR and SBOM hashes.
This same-workspace check is not the independent, protected-workflow reproducibility gate.

Tests include the real loopback CIO lifecycle and packaged stdio-proxy fixtures; they do not drive a real Burp instance.
Packaging verifies the embedded proxy and legal bundle and generates the CycloneDX SBOM. Local outputs are development
artifacts under `build/`, not a tagged release. Any subsequently uploaded PR/CI distribution is a test artifact,
not release or exact-byte Burp smoke evidence.

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
  smoke/publication gates in [RELEASING.md](RELEASING.md) remain mandatory. These changes do not authorize a release tag
  or publication of release assets.
