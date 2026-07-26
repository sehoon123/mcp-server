# Corresponding source

Independent MCP Bridge is distributed under GNU GPL version 3. This document identifies the durable source path for
the extension and its embedded stdio proxy.

## Extension source

Each release must publish all of the following beside the binary JAR:

- a source archive generated from the exact annotated release tag;
- the full Git commit SHA for that tag;
- `SHA256SUMS` covering the binary, source archive, SBOM, and legal files; and
- provenance linking the source SHA to the released JAR digest.

The canonical source repository is https://github.com/sehoon123/mcp-server. To reconstruct a released source tree:

```bash
git clone https://github.com/sehoon123/mcp-server.git
cd mcp-server
git checkout --detach <full-release-commit-sha>
./gradlew clean test embedProxyJar generateSbom --no-build-cache
```

Use JDK 21. The release commit, not a moving branch name, is the source identity. Build and release requirements are in
[`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md) and [`docs/RELEASING.md`](docs/RELEASING.md).

## Embedded stdio proxy source

The binary JAR contains `mcp-proxy-all.jar` plus `mcp-proxy-source.txt`. The metadata file records the proxy's canonical
repository, exact source commit, build command, artifact path, artifact SHA-256, and resolved runtime components. The
same metadata is tracked at [`libs/mcp-proxy-source.txt`](libs/mcp-proxy-source.txt).

For the currently pinned proxy, clone the recorded repository and check out the recorded full commit:

```bash
git clone https://github.com/sehoon123/mcp-proxy.git
cd mcp-proxy
git checkout --detach 5fc6a395af59b97d5250cf96002671b000cc0310
./gradlew clean test shadowJar writeRuntimeComponents --no-build-cache
```

The resulting proxy JAR must match the SHA-256 recorded in `mcp-proxy-source.txt` before it can be embedded. A future
proxy update must update the repository metadata and checksum atomically.

## Third-party source

Exact third-party Maven coordinates, versions, hashes, package URLs, and licenses are recorded in the release
CycloneDX SBOM. Their upstream source links are listed in [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md). Those
libraries remain under their respective licenses.

If a release artifact and its matching source archive are unavailable or disagree, do not use the artifact; report the
problem at https://github.com/sehoon123/mcp-server/issues.
