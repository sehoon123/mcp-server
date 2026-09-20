package net.portswigger.mcp.providers

import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.encodeToStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.nio.ByteBuffer
import java.nio.channels.Channels
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardOpenOption

internal const val MAX_PROVIDER_CONFIG_BYTES = 4 * 1024 * 1024
private val clientConfigJson = Json { prettyPrint = true; encodeDefaults = true }

/** Abort during UTF-8 serialization, before a backup or replacement can write an unreadable oversized config. */
@OptIn(ExperimentalSerializationApi::class)
internal fun encodeBoundedClientConfig(config: JsonObject): ByteArray {
    val output = object : ByteArrayOutputStream() {
        override fun write(value: Int) {
            requireCapacity(1)
            super.write(value)
        }

        override fun write(bytes: ByteArray, offset: Int, length: Int) {
            requireCapacity(length)
            super.write(bytes, offset, length)
        }

        private fun requireCapacity(additionalBytes: Int) {
            require(additionalBytes in 0..MAX_PROVIDER_CONFIG_BYTES - count) {
                "Updated client configuration exceeds the $MAX_PROVIDER_CONFIG_BYTES-byte safety limit"
            }
        }
    }
    clientConfigJson.encodeToStream(JsonObject.serializer(), config, output)
    return output.toByteArray()
}

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
