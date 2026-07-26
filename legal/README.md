# Packaged legal material

The release JAR copies this directory and the root distribution notices into `META-INF/legal/` under collision-safe
names. Dependency-provided generic `META-INF/LICENSE*` and `META-INF/NOTICE*` entries are excluded from the shaded
archive only after this reviewed bundle is supplied.

- `licenses/Apache-2.0.txt` is the Apache License 2.0 text extracted from the pinned Kotlin Gradle plugin 2.3.21 and is
  identical to the standard Apache License 2.0 text.
- `licenses/MIT-SLF4J.txt` is the license text from `slf4j-api` 2.0.17 and includes its copyright attribution.
- the root `LICENSE` contains GNU GPL version 3 for this project and the embedded proxy;
- the root `NOTICE.md`, `FORK_NOTICE.md`, `THIRD_PARTY_NOTICES.md`, and `CORRESPONDING_SOURCE.md` provide the
  distribution, fork, component, and source notices.

Reviewed on 2026-07-26. SHA-256 at review time:

```text
3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986  LICENSE
cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30  Apache-2.0.txt
8e0d2e086db1da82238c27929308de11db7453a29bc0da50331379105e5da8fd  MIT-SLF4J.txt
```

`runtime-licenses.properties` records an exact reviewed `group:name` to SPDX mapping. The build verifies these legal
file hashes and fails when a resolved extension or embedded-proxy coordinate is missing from the map or when a stale
mapping remains after a dependency is removed.
