package net.portswigger.mcp.providers

import burp.api.montoya.logging.Logging
import kotlinx.serialization.json.*
import net.portswigger.mcp.config.ConfigValidation
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.security.safeExceptionSummary
import java.io.File
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.charset.StandardCharsets
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.PosixFilePermission
import javax.swing.JFileChooser
import kotlin.io.path.exists
import kotlin.io.path.isDirectory
import kotlin.io.path.listDirectoryEntries
import kotlin.io.path.name

private const val MAX_PROVIDER_CONFIG_BYTES = 4L * 1024 * 1024
private val OWNER_ONLY_FILE_PERMISSIONS = setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE)

interface Provider {
    val name: String
    val installButtonText: String
    val confirmationText: String?
    fun install(config: McpConfig): String?
}

private const val BEARER_TOKEN_ENVIRONMENT_VARIABLE = "BURP_MCP_BEARER_TOKEN"

internal fun streamableHttpEndpoint(host: String, port: Int): String {
    val normalized = requireNotNull(ConfigValidation.normalizeLoopbackHost(host)) {
        "MCP endpoint host must be 127.0.0.1 or ::1"
    }
    val connectHost = if (':' in normalized) "[$normalized]" else normalized
    return "http://$connectHost:$port/mcp"
}

private fun readBoundedConfig(path: Path): String {
    requireNoSymlinkComponents(path)
    require(!Files.isSymbolicLink(path)) { "Refusing to read a symlinked client configuration" }
    val size = Files.size(path)
    require(size in 0..MAX_PROVIDER_CONFIG_BYTES) {
        "Client configuration exceeds the $MAX_PROVIDER_CONFIG_BYTES-byte safety limit"
    }
    return Files.readString(path, StandardCharsets.UTF_8)
}

internal fun atomicWritePrivate(path: Path, bytes: ByteArray, createBackup: Boolean) {
    val absolute = path.toAbsolutePath().normalize()
    val parent = absolute.parent ?: error("Destination has no parent directory")
    requireNoSymlinkComponents(parent)
    Files.createDirectories(parent)
    requireNoSymlinkComponents(parent)
    require(!Files.isSymbolicLink(absolute)) { "Refusing to replace a symlinked destination" }

    if (createBackup && Files.exists(absolute, LinkOption.NOFOLLOW_LINKS)) {
        val backup = absolute.resolveSibling("${absolute.fileName}.burp-mcp.bak")
        val backupTemp = Files.createTempFile(parent, ".burp-mcp-backup-", ".tmp")
        try {
            Files.copy(absolute, backupTemp, StandardCopyOption.REPLACE_EXISTING)
            forceFile(backupTemp)
            setOwnerOnlyPermissions(backupTemp)
            atomicReplace(backupTemp, backup)
            setOwnerOnlyPermissions(backup)
        } finally {
            Files.deleteIfExists(backupTemp)
        }
    }

    val temp = Files.createTempFile(parent, ".burp-mcp-write-", ".tmp")
    try {
        setOwnerOnlyPermissions(temp)
        FileChannel.open(temp, StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING).use { channel ->
            val buffer = ByteBuffer.wrap(bytes)
            while (buffer.hasRemaining()) channel.write(buffer)
            channel.force(true)
        }
        atomicReplace(temp, absolute)
        setOwnerOnlyPermissions(absolute)
    } finally {
        Files.deleteIfExists(temp)
    }
}

internal fun requireNoSymlinkComponents(path: Path) {
    val absolute = path.toAbsolutePath().normalize()
    var current = absolute.root ?: error("Path has no filesystem root")
    for (component in absolute) {
        current = current.resolve(component)
        if (Files.exists(current, LinkOption.NOFOLLOW_LINKS)) {
            require(!Files.isSymbolicLink(current)) { "Refusing to use a path containing a symbolic link" }
        }
    }
}

internal fun forceFile(path: Path) {
    FileChannel.open(path, StandardOpenOption.WRITE).use { it.force(true) }
}

internal fun atomicReplace(source: Path, destination: Path) {
    try {
        Files.move(
            source,
            destination,
            StandardCopyOption.ATOMIC_MOVE,
            StandardCopyOption.REPLACE_EXISTING,
        )
    } catch (_: AtomicMoveNotSupportedException) {
        Files.move(source, destination, StandardCopyOption.REPLACE_EXISTING)
    }
}

internal fun setOwnerOnlyPermissions(path: Path) {
    try {
        Files.setPosixFilePermissions(path, OWNER_ONLY_FILE_PERMISSIONS)
    } catch (_: UnsupportedOperationException) {
        // Windows applies the current user's inherited ACL; POSIX permissions are unavailable there.
    }
}

class ClaudeDesktopProvider(private val logging: Logging, private val proxyJarManager: ProxyJarManager) : Provider {

    private val claudeConfigFileName = "claude_desktop_config.json"
    private val serverName = "burp"

    override val name = "Claude Desktop"
    override val installButtonText = "Install to $name"
    override val confirmationText =
        "Install to $name?\n\n" +
            "The existing 'burp' entry will be replaced with:\n" +
            "- command: the Java runtime currently used by Burp\n" +
            "- args: the verified embedded proxy, current /mcp endpoint, and bearer-token environment option\n" +
            "- env: BURP_MCP_BEARER_TOKEN (sensitive)\n\n" +
            "The current $claudeConfigFileName will be backed up before an atomic update."

    override fun install(config: McpConfig): String {
        val proxyJarFile = proxyJarManager.getProxyJar()

        val path = configFilePath() ?: error("Could not find Claude config path")
        val content = Json.parseToJsonElement(readBoundedConfig(path)).jsonObject.toMutableMap()

        val javaPath = javaPath()
        logging.logToOutput("Using the current Burp Java runtime for the MCP proxy")

        val mcpUrl = streamableHttpEndpoint(config.host, config.port)
        val burpServerConfig = buildJsonObject {
            put("command", JsonPrimitive(javaPath))
            put("args", buildJsonArray {
                add(JsonPrimitive("-jar"))
                add(JsonPrimitive(proxyJarFile.toString()))
                add(JsonPrimitive("--mcp-url"))
                add(JsonPrimitive(mcpUrl))
                add(JsonPrimitive("--bearer-token-env"))
                add(JsonPrimitive(BEARER_TOKEN_ENVIRONMENT_VARIABLE))
            })
            put("env", buildJsonObject {
                put(BEARER_TOKEN_ENVIRONMENT_VARIABLE, JsonPrimitive(config.localBearerToken))
            })
        }

        val mcpServers = content["mcpServers"]?.jsonObject?.toMutableMap() ?: mutableMapOf()
        mcpServers[serverName] = burpServerConfig
        content["mcpServers"] = JsonObject(mcpServers)

        val json = Json {
            prettyPrint = true
            encodeDefaults = true
        }
        atomicWritePrivate(
            path,
            json.encodeToString(JsonObject.serializer(), JsonObject(content)).toByteArray(StandardCharsets.UTF_8),
            createBackup = true,
        )

        logging.logToOutput("Installed Burp MCP Server to Claude Desktop config with an atomic owner-only update")

        return "Installation successful. Updated command and proxy args for $mcpUrl; " +
            "the bearer environment value was replaced (redacted), and a backup was created. " +
            "Please restart $name if it is currently running."
    }

    private fun configFilePath(): Path? {
        val os = System.getProperty("os.name").lowercase()
        val home = System.getProperty("user.home")

        val candidatePaths = when {
            os.contains("win") -> windowsCandidatePaths(home)
            os.contains("mac") || os.contains("darwin") -> listOf(
                Path.of(home, "Library", "Application Support", "Claude")
            )
            os.contains("linux") -> listOf(Path.of(home, ".config", "Claude"))
            else -> return null
        }

        val existingPaths = candidatePaths.filter { it.exists() }
        if (existingPaths.size > 1) {
            logging.logToOutput("Warning: multiple Claude Desktop config directories found; using ${existingPaths.first()}: $existingPaths")
        }
        val basePath = existingPaths.firstOrNull() ?: return null

        val configFile = basePath.resolve(claudeConfigFileName)
        if (!configFile.exists()) {
            createDefaultConfig(configFile)
        }

        return configFile
    }

    internal fun windowsCandidatePaths(home: String): List<Path> {
        val traditional = Path.of(home, "AppData", "Roaming", "Claude")

        // Windows Store installs place config under a package directory with a random suffix:
        // AppData\Local\Packages\Claude_<suffix>\LocalCache\Roaming\Claude
        val packagesDir = Path.of(home, "AppData", "Local", "Packages")
        val storePaths = if (packagesDir.exists()) {
            packagesDir.listDirectoryEntries()
                .filter { it.isDirectory() && it.name.startsWith("Claude_") }
                .map { it.resolve("LocalCache").resolve("Roaming").resolve("Claude") }
        } else {
            emptyList()
        }

        return listOf(traditional) + storePaths
    }

    private fun createDefaultConfig(path: Path): Boolean {
        try {
            val defaultConfig = buildJsonObject {
                put("mcpServers", buildJsonObject {})
            }

            val json = Json {
                prettyPrint = true
                encodeDefaults = true
            }

            atomicWritePrivate(
                path,
                json.encodeToString(JsonObject.serializer(), defaultConfig).toByteArray(StandardCharsets.UTF_8),
                createBackup = false,
            )
            logging.logToOutput("Created a default Claude Desktop config")
            return true
        } catch (e: Exception) {
            logging.logToError("Failed to create default Claude Desktop config: ${safeExceptionSummary(e)}")
            return false
        }
    }

    private fun javaPath(): String {
        val javaHome = System.getProperty("java.home")
        val os = System.getProperty("os.name").lowercase()

        return if (os.contains("win")) {
            "$javaHome\\bin\\java.exe"
        } else {
            "$javaHome/bin/java"
        }
    }
}

class ManualProxyInstallerProvider(private val logging: Logging, private val proxyJarManager: ProxyJarManager) :
    Provider {
    override val name = "Proxy jar"
    override val installButtonText = "Extract server proxy jar"
    override val confirmationText = null

    override fun install(config: McpConfig): String? {
        val proxyJarFile = proxyJarManager.getProxyJar()

        val fileChooser = JFileChooser().apply {
            dialogTitle = "Save proxy jar"
            selectedFile = File("mcp-proxy.jar")
        }

        if (fileChooser.showSaveDialog(null) != JFileChooser.APPROVE_OPTION) {
            return null
        }

        val destinationFile = fileChooser.selectedFile
        try {
            atomicWritePrivate(
                destinationFile.toPath(),
                Files.readAllBytes(proxyJarFile),
                createBackup = destinationFile.exists(),
            )
            logging.logToOutput("MCP proxy jar saved successfully")
        } catch (ex: Exception) {
            logging.logToError("Failed to save installer: ${safeExceptionSummary(ex)}")
            throw ex
        }

        return "Extracted proxy jar to $destinationFile"
    }
}