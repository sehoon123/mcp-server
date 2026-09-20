package net.portswigger.mcp.providers

import java.io.InputStream
import java.nio.ByteBuffer
import java.nio.channels.Channels
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardOpenOption

internal const val MAX_PROVIDER_CONFIG_BYTES = 4 * 1024 * 1024

internal fun readBoundedClientConfig(path: Path): String {
    requireNoSymlinkComponents(path)
    require(Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
        "Client configuration must be a regular file"
    }
    return Files.newByteChannel(path, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS).use { channel ->
        require(channel.size() in 0..MAX_PROVIDER_CONFIG_BYTES.toLong()) {
            "Client configuration exceeds the $MAX_PROVIDER_CONFIG_BYTES-byte safety limit"
        }
        readBoundedClientConfig(Channels.newInputStream(channel))
    }
}

/** Bound the actual read as well as the initial file size: another process can grow the file while it is read. */
internal fun readBoundedClientConfig(input: InputStream): String {
    val bytes = input.readNBytes(MAX_PROVIDER_CONFIG_BYTES + 1)
    require(bytes.size <= MAX_PROVIDER_CONFIG_BYTES) {
        "Client configuration exceeds the $MAX_PROVIDER_CONFIG_BYTES-byte safety limit"
    }
    // Preserve Files.readString's strict UTF-8 behavior; never silently replace malformed configuration bytes.
    return StandardCharsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(bytes)).toString()
}
