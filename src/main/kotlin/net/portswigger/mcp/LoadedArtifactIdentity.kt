package net.portswigger.mcp

import java.net.URL
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.BasicFileAttributes
import java.security.MessageDigest
import java.util.HexFormat

private const val MAX_LOADED_ARTIFACT_BYTES = 512L * 1024 * 1024

/** Best-effort, path-free identity for the exact regular JAR from which the extension classes were loaded. */
internal object LoadedArtifactIdentity {
    fun currentSha256(anchor: Class<*> = LoadedArtifactIdentity::class.java): String? =
        sha256ForCodeSource(anchor.protectionDomain?.codeSource?.location)

    internal fun sha256ForCodeSource(location: URL?): String? = runCatching {
        if (location?.protocol != "file") return null
        val path = java.nio.file.Path.of(location.toURI())
        val attributes = Files.readAttributes(path, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
        if (!attributes.isRegularFile || attributes.size() !in 1..MAX_LOADED_ARTIFACT_BYTES) return null
        FileChannel.open(path, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS).use { channel ->
            if (channel.size() != attributes.size()) return null
            val digest = MessageDigest.getInstance("SHA-256")
            val buffer = ByteBuffer.allocate(64 * 1024)
            while (channel.read(buffer) >= 0) {
                if (buffer.position() == 0) continue
                buffer.flip()
                digest.update(buffer)
                buffer.clear()
            }
            if (channel.size() != attributes.size()) return null
            val after = Files.readAttributes(path, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
            if (
                !after.isRegularFile || after.size() != attributes.size() ||
                after.lastModifiedTime() != attributes.lastModifiedTime() || after.fileKey() != attributes.fileKey()
            ) return null
            HexFormat.of().formatHex(digest.digest())
        }
    }.getOrNull()
}
