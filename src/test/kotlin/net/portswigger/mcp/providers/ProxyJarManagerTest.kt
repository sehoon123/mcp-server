package net.portswigger.mcp.providers

import burp.api.montoya.logging.Logging
import io.mockk.mockk
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import java.util.HexFormat
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class ProxyJarManagerTest {
    @Test
    fun `proxy extraction refuses a symlinked parent directory`(@TempDir directory: Path) {
        val realDirectory = directory.resolve("real").also { Files.createDirectory(it) }
        val linkedDirectory = directory.resolve("linked")
        runCatching { Files.createSymbolicLink(linkedDirectory, realDirectory.fileName) }.getOrElse { return }
        val manager = ProxyJarManager(
            logging = mockk<Logging>(relaxed = true),
            resourceProvider = { null },
            proxyDirectory = linkedDirectory,
        )

        val error = assertThrows<IllegalArgumentException> { manager.getProxyJar() }

        assertTrue(error.message.orEmpty().contains("symbolic link"))
        assertTrue(Files.notExists(realDirectory.resolve("mcp-proxy-all.jar")))
    }

    @Test
    fun `current extracted proxy does not read the large jar resource again`(@TempDir proxyDirectory: Path) {
        val proxyBytes = ByteArray(2 * 1024 * 1024) { (it % 251).toByte() }
        val expectedHash = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(proxyBytes))
        val metadata = "SHA-256: $expectedHash\n"
        var proxyResourceReads = 0

        val manager = ProxyJarManager(
            logging = mockk<Logging>(relaxed = true),
            resourceProvider = { name ->
                when (name) {
                    "mcp-proxy-source.txt" -> metadata.byteInputStream()
                    "mcp-proxy-all.jar" -> {
                        proxyResourceReads++
                        proxyBytes.inputStream()
                    }
                    else -> null
                }
            },
            proxyDirectory = proxyDirectory,
        )

        val extracted = manager.getProxyJar()
        assertContentEquals(proxyBytes, Files.readAllBytes(extracted))
        assertEquals(1, proxyResourceReads)

        val unchanged = manager.getProxyJar()
        assertEquals(extracted, unchanged)
        assertEquals(1, proxyResourceReads, "fast path must not open the 14.7 MB packaged JAR")

        Files.writeString(proxyDirectory.resolve("mcp-proxy-all.jar.version"), "stale")
        manager.getProxyJar()
        assertEquals(2, proxyResourceReads)
        assertTrue(Files.exists(extracted))

        Files.writeString(extracted, "tampered")
        manager.getProxyJar()
        assertEquals(3, proxyResourceReads, "a matching version marker must not bypass JAR verification")
        assertContentEquals(proxyBytes, Files.readAllBytes(extracted))
    }
}
