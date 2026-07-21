package net.portswigger.mcp.providers

import burp.api.montoya.logging.Logging
import java.io.IOException
import java.io.InputStream
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.security.DigestInputStream
import java.security.MessageDigest
import java.util.HexFormat
import kotlin.io.path.exists
import kotlin.io.path.readText

class ProxyJarManager(
    private val logging: Logging,
    private val resourceProvider: (String) -> InputStream? = {
        ProxyJarManager::class.java.classLoader.getResourceAsStream(it)
    },
    private val proxyDirectory: Path = defaultProxyDirectory(),
) {

    companion object {
        private const val PROXY_JAR_NAME = "mcp-proxy-all.jar"
        private const val PROXY_METADATA_NAME = "mcp-proxy-source.txt"
        private val SHA256_PATTERN = Regex("(?m)^SHA-256: ([a-f0-9]{64})$")

        private fun defaultProxyDirectory(): Path {
            val os = System.getProperty("os.name").lowercase()
            val home = System.getProperty("user.home")

            return when {
                os.contains("win") -> Path.of(home, "AppData", "Roaming", "BurpSuite", "mcp-proxy")
                os.contains("mac") || os.contains("darwin") -> Path.of(home, ".BurpSuite", "mcp-proxy")
                os.contains("linux") || os.contains("unix") -> Path.of(home, ".BurpSuite", "mcp-proxy")
                else -> throw RuntimeException("Unsupported OS: $os")
            }
        }
    }

    fun getProxyJar(): Path {
        val proxyJarPath = getBurpProxyJarPath()
        val versionFilePath = proxyJarPath.resolveSibling("$PROXY_JAR_NAME.version")

        if (!proxyJarPath.parent.exists()) {
            try {
                Files.createDirectories(proxyJarPath.parent)
            } catch (e: IOException) {
                throw RuntimeException("Failed to create directory: ${proxyJarPath.parent}", e)
            }
        }

        val expectedHash = expectedProxyHash()
        val currentHash = if (versionFilePath.exists()) versionFilePath.readText().trim() else null
        if (proxyJarPath.exists() && currentHash == expectedHash) {
            return proxyJarPath
        }

        extractProxyJar(proxyJarPath, versionFilePath, expectedHash)
        return proxyJarPath
    }

    private fun expectedProxyHash(): String {
        val metadata = resourceProvider(PROXY_METADATA_NAME)
            ?.bufferedReader()
            ?.use { it.readText() }
            ?: throw RuntimeException("Could not find $PROXY_METADATA_NAME in extension resources")

        return SHA256_PATTERN.find(metadata)?.groupValues?.get(1)
            ?: throw RuntimeException("Could not find proxy SHA-256 in $PROXY_METADATA_NAME")
    }

    private fun extractProxyJar(proxyJarPath: Path, versionFilePath: Path, expectedHash: String) {
        val tempFile = Files.createTempFile(proxyJarPath.parent, "temp-", ".jar")
        try {
            val digest = MessageDigest.getInstance("SHA-256")
            val resource = resourceProvider(PROXY_JAR_NAME)
                ?: throw RuntimeException("Could not find $PROXY_JAR_NAME in extension resources")

            resource.use { input ->
                DigestInputStream(input, digest).use { digestInput ->
                    Files.copy(digestInput, tempFile, StandardCopyOption.REPLACE_EXISTING)
                }
            }

            val actualHash = HexFormat.of().formatHex(digest.digest())
            check(actualHash == expectedHash) {
                "Packaged proxy checksum mismatch: expected $expectedHash, got $actualHash"
            }

            Files.move(tempFile, proxyJarPath, StandardCopyOption.REPLACE_EXISTING)
            Files.writeString(versionFilePath, expectedHash)

            if (!System.getProperty("os.name").lowercase().contains("win")) {
                proxyJarPath.toFile().setExecutable(true)
            }

            logging.logToOutput("Extracted proxy jar to: $proxyJarPath")
        } catch (e: Exception) {
            Files.deleteIfExists(tempFile)
            throw RuntimeException("Failed to extract proxy jar to: $proxyJarPath", e)
        }
    }

    private fun getBurpProxyJarPath(): Path = proxyDirectory.resolve(PROXY_JAR_NAME)
}
