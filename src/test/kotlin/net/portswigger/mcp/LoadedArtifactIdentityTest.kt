package net.portswigger.mcp

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import java.util.HexFormat

class LoadedArtifactIdentityTest {
    @TempDir
    lateinit var tempDir: Path

    @Test
    fun `hashes one regular code-source file without exposing its path`() {
        val artifact = tempDir.resolve("candidate.jar")
        val content = "exact-candidate-bytes".toByteArray()
        Files.write(artifact, content)
        val expected = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(content))

        assertEquals(expected, LoadedArtifactIdentity.sha256ForCodeSource(artifact.toUri().toURL()))
    }

    @Test
    fun `rejects directory non-file and symlink code sources`() {
        assertNull(LoadedArtifactIdentity.sha256ForCodeSource(tempDir.toUri().toURL()))
        assertNull(LoadedArtifactIdentity.sha256ForCodeSource(null))

        val artifact = tempDir.resolve("candidate.jar")
        Files.writeString(artifact, "candidate")
        val link = tempDir.resolve("candidate-link.jar")
        Files.createSymbolicLink(link, artifact)
        assertNull(LoadedArtifactIdentity.sha256ForCodeSource(link.toUri().toURL()))
    }
}
