# Release dependency review inputs

`release-maven-coordinates.txt` is the canonical, sorted, LF-terminated Maven coordinate set pinned by the existing
formal release workflows. It remains frozen with those workflows; it is not the updated v4.12 candidate graph. It combines both server and embedded-proxy Gradle lockfiles, both resolved project-plugin
`buildEnvironment` graphs after conflict selection, and the explicitly reviewed implementations of both settings
plugins.

The immutable draft workflow derives the set again from the exact server and proxy commits and requires byte-for-byte
equality before querying OSV. That frozen contract is 204 unique coordinates with SHA-256
`2253cc639c78b44cd2c8356dd868e4e95287ca03af5a7cabce85495517a02d51`. Do not edit the file or its expected identity
without reviewing the dependency, integrity, license, vulnerability, and release-policy changes together.

## v4.12 local candidate preflight

`v4.12-candidate-maven-coordinates.txt` separately records the complete updated server/proxy graph for local pre-tag
checking: **206** unique coordinates, SHA-256
`585bc63c66d07d5aa54e144cfe179a8bde444ddc5b0238dca79532406a71a688`.
It includes both lockfiles, both selected project-plugin graphs, and both reviewed settings-plugin implementations;
no build/test dependency is excluded from the query. Kotlin 2.4.0 ABI-compatibility tooling is included alongside 2.4.20.
The obsolete `kotlinInternalAbiValidation` configuration no longer exists in either project; its stale lock bindings
were removed and the current complete graphs resolved again, not filtered to hide an advisory.

The 2026-09-18 audit cleanup removes only the unused test-side `ktor-client-content-negotiation` and its JVM coordinate
from the prior 208-coordinate baseline. Both are absent from the resolved server graph and pinned proxy lockfile;
runtime dependencies, dependency versions, and the frozen formal release contract are unchanged. This graph update
is not fresh vulnerability evidence.

Use the existing `scripts/release_vulnerability_gate.py` with this file, `--expected-count 206`, and the exact hash above.
Generate graph reports and fresh OSV/npm results against the clean committed server and the exact embedded-proxy source
commit. The script validates supplied identities but does not independently prove checkout identity; the caller must
verify those commits and clean source state. Previous responses, editable working trees, and passing contract fixtures
are not immutable pre-tag evidence.

This local baseline does **not** change the frozen formal workflow's 204-coordinate producer/consumer contract, the
RC7 observation identities, or the blocked v4.11 predecessor bridge. Formal publication needs a separately reviewed,
end-to-end workflow/baseline transition and all remaining release gates; do not patch just one count or reuse a manual
draft as an attested release.

Release vulnerability evidence consists of the exact-coordinate OSV response and the normalized dev-inclusive npm audit
result. The gate rejects malformed or incomplete OSV responses, every OSV finding, npm high/critical findings, and npm
nodes outside the checked-in moderate conformance-development exception.
