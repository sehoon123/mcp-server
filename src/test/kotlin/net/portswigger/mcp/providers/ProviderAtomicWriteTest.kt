package net.portswigger.mcp.providers

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermission
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class ProviderAtomicWriteTest {
    @Test
    fun `atomic private write creates a current backup and owner-only target`(@TempDir directory: Path) {
        val target = directory.resolve("client.json")
        target.writeText("old")

        atomicWritePrivate(target, "new".toByteArray(), createBackup = true)

        assertEquals("new", target.readText())
        assertEquals("old", directory.resolve("client.json.burp-mcp.bak").readText())
        runCatching { Files.getPosixFilePermissions(target) }.getOrNull()?.let { permissions ->
            assertEquals(
                setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE),
                permissions,
            )
        }
    }

    @Test
    fun `atomic private write refuses a symlinked parent directory`(@TempDir directory: Path) {
        val realDirectory = directory.resolve("real").also { Files.createDirectory(it) }
        val linkedDirectory = directory.resolve("linked")
        runCatching { Files.createSymbolicLink(linkedDirectory, realDirectory.fileName) }.getOrElse { return }

        val error = assertThrows<IllegalArgumentException> {
            atomicWritePrivate(linkedDirectory.resolve("client.json"), "poisoned".toByteArray(), createBackup = true)
        }

        assertTrue(error.message.orEmpty().contains("symbolic link"))
        assertTrue(Files.notExists(realDirectory.resolve("client.json")))
    }

    @Test
    fun `atomic private write refuses to follow a destination symlink`(@TempDir directory: Path) {
        val real = directory.resolve("real.json").also { it.writeText("safe") }
        val link = directory.resolve("client.json")
        runCatching { Files.createSymbolicLink(link, real.fileName) }.getOrElse { return }

        val error = assertThrows<IllegalArgumentException> {
            atomicWritePrivate(link, "poisoned".toByteArray(), createBackup = true)
        }

        assertTrue(error.message.orEmpty().contains("symlink"))
        assertEquals("safe", real.readText())
    }
}
