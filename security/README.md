# Release dependency review inputs

`release-maven-coordinates.txt` is the canonical, sorted, LF-terminated set of exact Maven coordinates reviewed for the
current release candidate. It combines both server and embedded-proxy Gradle lockfiles, both resolved project-plugin
`buildEnvironment` graphs after conflict selection, and the explicitly reviewed implementations of both settings
plugins.

The immutable draft workflow derives the set again from the exact server and proxy commits and requires byte-for-byte
equality before querying OSV. The current contract is 204 unique coordinates with SHA-256
`2253cc639c78b44cd2c8356dd868e4e95287ca03af5a7cabce85495517a02d51`. Do not edit the file or its expected identity
without reviewing the dependency, integrity, license, vulnerability, and release-policy changes together.

Release vulnerability evidence consists of the exact-coordinate OSV response and the normalized dev-inclusive npm audit
result. The gate rejects malformed or incomplete OSV responses, every OSV finding, npm high/critical findings, and npm
nodes outside the checked-in moderate conformance-development exception.
