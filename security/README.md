# Release dependency review inputs

`release-maven-coordinates.txt` is the canonical, sorted, LF-terminated Maven coordinate set pinned by the formal release
workflows. It combines both server and embedded-proxy Gradle lockfiles, both resolved project-plugin `buildEnvironment`
graphs after conflict selection, and the explicitly reviewed implementations of both settings plugins.

The immutable draft workflow derives the set again from the exact server and proxy commits and requires byte-for-byte
equality before querying OSV. The current contract is **206** unique coordinates with SHA-256
`db331e7bc6b3a922c2528782a955d18147dc98a7ffbccf3bb1c6a30184283816`. Do not edit the file or its expected identity without
reviewing the dependency, integrity, license, vulnerability, and release-policy changes together.

## v4.12.0 graph transition

The v4.12.0 graph replaces the earlier frozen 204-coordinate set and supersedes the separate `v4.12-candidate` local
baseline, which this canonical file now carries. It changes the reviewed candidate graph only in the test-only Jackson
BOM after the 2026-10-30 OSV preflight reported `tools.jackson.core:jackson-core:3.1.5` and
`tools.jackson.core:jackson-databind:3.1.5`:
`gradle/libs.versions.toml` moves `jackson-test` to `3.1.7`, which resolves `jackson-core`, `jackson-databind`,
`jackson-dataformat-yaml`, and `jackson-bom` to `3.1.7` on the test classpaths only. No runtime, proxy, plugin, or
shipped dependency changes, so the extension JAR is unaffected; the lockfile and dependency-verification metadata carry
the reviewed additions.

Kotlin 2.4.20 ABI-compatibility tooling is included alongside 2.4.20, and the obsolete `kotlinInternalAbiValidation`
configuration is absent from both projects. No build/test dependency is excluded from the query.

Use the existing `scripts/release_vulnerability_gate.py` with `--expected-count 206` and the hash above. Generate graph
reports and fresh OSV/npm results against the clean committed server and the exact embedded-proxy source commit. The
script validates supplied identities but does not independently prove checkout identity; the caller must verify those
commits and clean source state. Previous responses, editable working trees, and passing contract fixtures are not
immutable pre-tag evidence.

Release vulnerability evidence consists of the exact-coordinate OSV response and the normalized dev-inclusive npm audit
result. The gate rejects malformed or incomplete OSV responses, every OSV finding, npm high/critical findings, and npm
nodes outside the checked-in moderate conformance-development exception.
