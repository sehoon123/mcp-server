package net.portswigger.mcp.config

import burp.api.montoya.logging.Logging
import burp.api.montoya.persistence.PersistedObject
import burp.api.montoya.persistence.Preferences
import kotlinx.coroutines.CancellationException
import net.portswigger.mcp.security.safeExceptionSummary
import java.lang.ref.WeakReference
import java.security.SecureRandom
import java.util.Base64
import java.util.concurrent.CopyOnWriteArrayList
import kotlin.properties.ReadWriteProperty
import kotlin.reflect.KProperty

internal const val MIN_AUDIT_RETENTION_ENTRIES = 50
internal const val MAX_AUDIT_RETENTION_ENTRIES = 1000
internal const val DEFAULT_AUDIT_RETENTION_ENTRIES = 250

private const val TARGET_SEPARATOR = "\n"
private const val LEGACY_PROJECT_BEARER_TOKEN_KEY = "localBearerToken"
private const val INSTALLATION_BEARER_TOKEN_KEY = "independentMcpBridge.localBearerToken.v1"
private const val AUDIT_RETENTION_ENTRIES_KEY = "auditRetentionEntries"
private const val APPROVAL_YOLO_MODE_KEY = "approvalYoloMode"
private val LOCAL_BEARER_TOKEN_PATTERN = Regex("[A-Za-z0-9_-]{43,128}")
private val INSTALLATION_BEARER_TOKEN_LOCK = Any()

internal fun isValidLocalBearerToken(value: String): Boolean = LOCAL_BEARER_TOKEN_PATTERN.matches(value)

class McpConfig(
    private val storage: PersistedObject,
    private val logging: Logging,
    installationPreferences: Preferences,
) {
    private val localBearerTokens = InstallationBearerTokenStore(installationPreferences, storage, logging)

    var enabled by storage.boolean(true)
    var configEditingTooling by storage.boolean(false)
    var host by storage.string("127.0.0.1")
    var port by storage.int(9876)
    var requireHttpRequestApproval by storage.boolean(true)

    @Volatile
    private var cachedApprovalYoloMode = runCatching {
        storage.getBoolean(APPROVAL_YOLO_MODE_KEY)
    }.getOrNull() ?: false

    /** Local operator override that bypasses approval prompts while retaining validation and execution safeguards. */
    var approvalYoloMode: Boolean
        get() = cachedApprovalYoloMode
        @Synchronized
        set(value) {
            if (cachedApprovalYoloMode == value) return
            storage.setBoolean(APPROVAL_YOLO_MODE_KEY, value)
            cachedApprovalYoloMode = value
        }

    var requireRequestActionApproval: Boolean
        get() = storage.getBoolean("requireRequestActionApproval") ?: true
        set(value) {
            val previous = requireRequestActionApproval
            storage.setBoolean("requireRequestActionApproval", value)
            if (previous != value) notifyRequestActionApprovalChanged()
        }
    var requireScopeChangeApproval: Boolean
        get() = storage.getBoolean("requireScopeChangeApproval") ?: true
        set(value) {
            val previous = requireScopeChangeApproval
            storage.setBoolean("requireScopeChangeApproval", value)
            if (previous != value) notifyScopeChangeApprovalChanged()
        }
    var requireDataAccessApproval by storage.boolean(true)
    var emergencyReadOnlyMode by storage.boolean(false)
    var auditLoggingEnabled by storage.boolean(true)
    var auditRetentionEntries: Int
        get() = (storage.getInteger(AUDIT_RETENTION_ENTRIES_KEY) ?: DEFAULT_AUDIT_RETENTION_ENTRIES)
            .coerceIn(MIN_AUDIT_RETENTION_ENTRIES, MAX_AUDIT_RETENTION_ENTRIES)
        set(value) {
            storage.setInteger(
                AUDIT_RETENTION_ENTRIES_KEY,
                value.coerceIn(MIN_AUDIT_RETENTION_ENTRIES, MAX_AUDIT_RETENTION_ENTRIES),
            )
        }

    private var _alwaysAllowHttpHistory by storage.boolean(false)
    var alwaysAllowHttpHistory: Boolean
        get() = _alwaysAllowHttpHistory
        set(value) {
            if (_alwaysAllowHttpHistory != value) {
                _alwaysAllowHttpHistory = value
                notifyDataAccessChanged()
            }
        }

    private var _alwaysAllowSiteMap by storage.boolean(false)
    var alwaysAllowSiteMap: Boolean
        get() = _alwaysAllowSiteMap
        set(value) {
            if (_alwaysAllowSiteMap != value) {
                _alwaysAllowSiteMap = value
                notifyDataAccessChanged()
            }
        }

    private var _alwaysAllowWebSocketHistory by storage.boolean(false)
    var alwaysAllowWebSocketHistory: Boolean
        get() = _alwaysAllowWebSocketHistory
        set(value) {
            if (_alwaysAllowWebSocketHistory != value) {
                _alwaysAllowWebSocketHistory = value
                notifyDataAccessChanged()
            }
        }

    private var _alwaysAllowOrganizer by storage.boolean(false)
    var alwaysAllowOrganizer: Boolean
        get() = _alwaysAllowOrganizer
        set(value) {
            if (_alwaysAllowOrganizer != value) {
                _alwaysAllowOrganizer = value
                notifyDataAccessChanged()
            }
        }

    private var _alwaysAllowScannerIssues by storage.boolean(false)
    var alwaysAllowScannerIssues: Boolean
        get() = _alwaysAllowScannerIssues
        set(value) {
            if (_alwaysAllowScannerIssues != value) {
                _alwaysAllowScannerIssues = value
                notifyDataAccessChanged()
            }
        }

    private var _alwaysAllowCollaboratorInteractions by storage.boolean(false)
    var alwaysAllowCollaboratorInteractions: Boolean
        get() = _alwaysAllowCollaboratorInteractions
        set(value) {
            if (_alwaysAllowCollaboratorInteractions != value) {
                _alwaysAllowCollaboratorInteractions = value
                notifyDataAccessChanged()
            }
        }

    var filterConfigCredentials by storage.boolean(true)

    /** Per-installation credential used only by the loopback MCP HTTP endpoint. */
    val localBearerToken: String
        get() = localBearerTokens.current()

    fun rotateLocalBearerToken(): String = localBearerTokens.rotate()

    private var _autoApproveTargets by storage.stringList("")
    @Volatile
    private var cachedTargetsRaw: String? = null
    @Volatile
    private var cachedTargets: List<String> = emptyList()
    private val targetsChangeListeners = CopyOnWriteArrayList<ListenerRegistration>()
    private val dataAccessChangeListeners = CopyOnWriteArrayList<ListenerRegistration>()
    private val requestActionApprovalChangeListeners = CopyOnWriteArrayList<ListenerRegistration>()
    private val scopeChangeApprovalChangeListeners = CopyOnWriteArrayList<ListenerRegistration>()

    var autoApproveTargets: String
        get() = _autoApproveTargets
        set(value) {
            val normalized = normalizeTargetList(value).joinToString(TARGET_SEPARATOR)
            if (_autoApproveTargets != normalized) {
                _autoApproveTargets = normalized
                cacheTargets(normalized)
                notifyTargetsChanged()
            }
        }

    init {
        val normalized = normalizeTargetList(_autoApproveTargets).joinToString(TARGET_SEPARATOR)
        if (normalized != _autoApproveTargets) {
            _autoApproveTargets = normalized
        }
        cacheTargets(normalized)
    }

    fun addAutoApproveTarget(target: String): Boolean {
        val normalized = TargetValidation.normalizeTarget(target.trim()) ?: return false
        val currentTargets = getAutoApproveTargetsList()
        if (currentTargets.contains(normalized)) return false
        autoApproveTargets = (currentTargets + normalized).joinToString(TARGET_SEPARATOR)
        return true
    }

    fun removeAutoApproveTarget(target: String): Boolean {
        val normalized = TargetValidation.normalizeTarget(target.trim()) ?: return false
        val currentTargets = getAutoApproveTargetsList()
        val newTargets = currentTargets.filter { it != normalized }
        if (newTargets.size != currentTargets.size) {
            autoApproveTargets = newTargets.joinToString(TARGET_SEPARATOR)
            return true
        }
        return false
    }

    fun getAutoApproveTargetsList(): List<String> {
        val raw = _autoApproveTargets
        if (raw == cachedTargetsRaw) return cachedTargets
        return cacheTargets(raw)
    }

    @Synchronized
    private fun cacheTargets(raw: String): List<String> {
        if (raw == cachedTargetsRaw) return cachedTargets
        val parsed = normalizeTargetList(raw)
        cachedTargets = parsed
        cachedTargetsRaw = raw
        return parsed
    }

    fun clearAutoApproveTargets() {
        autoApproveTargets = ""
    }

    /** Restores every persisted approval bypass to the secure prompt-by-default state. */
    fun resetPersistentApprovals() {
        approvalYoloMode = false
        requireHttpRequestApproval = true
        clearAutoApproveTargets()
        requireRequestActionApproval = true
        requireScopeChangeApproval = true
        requireDataAccessApproval = true
        alwaysAllowHttpHistory = false
        alwaysAllowSiteMap = false
        alwaysAllowWebSocketHistory = false
        alwaysAllowOrganizer = false
        alwaysAllowScannerIssues = false
        alwaysAllowCollaboratorInteractions = false
    }

    fun addTargetsChangeListener(listener: () -> Unit): ListenerHandle {
        val registration = ListenerRegistration(listener)
        targetsChangeListeners.add(registration)
        return ListenerHandle { removeTargetsChangeListener(registration) }
    }

    private fun removeTargetsChangeListener(registration: ListenerRegistration) {
        targetsChangeListeners.remove(registration)
    }

    private fun notifyTargetsChanged() {
        cleanupStaleListeners(targetsChangeListeners)
        val listeners = targetsChangeListeners.mapNotNull { it.listener.get() }
        listeners.forEach { listener ->
            try {
                listener()
            } catch (e: Exception) {
                logging.logToError("Targets change listener failed: ${safeExceptionSummary(e)}")
            }
        }
    }

    fun addDataAccessChangeListener(listener: () -> Unit): ListenerHandle {
        val registration = ListenerRegistration(listener)
        dataAccessChangeListeners.add(registration)
        return ListenerHandle { removeDataAccessChangeListener(registration) }
    }

    private fun removeDataAccessChangeListener(registration: ListenerRegistration) {
        dataAccessChangeListeners.remove(registration)
    }

    private fun notifyDataAccessChanged() {
        cleanupStaleListeners(dataAccessChangeListeners)
        val listeners = dataAccessChangeListeners.mapNotNull { it.listener.get() }
        listeners.forEach { listener ->
            try {
                listener()
            } catch (e: Exception) {
                logging.logToError("Data access change listener failed: ${safeExceptionSummary(e)}")
            }
        }
    }

    fun addRequestActionApprovalChangeListener(listener: () -> Unit): ListenerHandle {
        val registration = ListenerRegistration(listener)
        requestActionApprovalChangeListeners.add(registration)
        return ListenerHandle { requestActionApprovalChangeListeners.remove(registration) }
    }

    private fun notifyRequestActionApprovalChanged() {
        cleanupStaleListeners(requestActionApprovalChangeListeners)
        val listeners = requestActionApprovalChangeListeners.mapNotNull { it.listener.get() }
        listeners.forEach { listener ->
            try {
                listener()
            } catch (e: Exception) {
                logging.logToError("Request action approval listener failed: ${safeExceptionSummary(e)}")
            }
        }
    }

    fun addScopeChangeApprovalChangeListener(listener: () -> Unit): ListenerHandle {
        val registration = ListenerRegistration(listener)
        scopeChangeApprovalChangeListeners.add(registration)
        return ListenerHandle { scopeChangeApprovalChangeListeners.remove(registration) }
    }

    private fun notifyScopeChangeApprovalChanged() {
        cleanupStaleListeners(scopeChangeApprovalChangeListeners)
        val listeners = scopeChangeApprovalChangeListeners.mapNotNull { it.listener.get() }
        listeners.forEach { listener ->
            try {
                listener()
            } catch (e: Exception) {
                logging.logToError("Scope change approval listener failed: ${safeExceptionSummary(e)}")
            }
        }
    }

    private fun cleanupStaleListeners(listenerList: CopyOnWriteArrayList<ListenerRegistration>) {
        val staleListeners = listenerList.filter { it.listener.get() == null }
        listenerList.removeAll(staleListeners)
    }

    fun cleanup() {
        targetsChangeListeners.clear()
        dataAccessChangeListeners.clear()
        requestActionApprovalChangeListeners.clear()
        scopeChangeApprovalChangeListeners.clear()
    }
}

fun PersistedObject.boolean(default: Boolean = false) =
    PersistedDelegate(getter = { key -> getBoolean(key) ?: default }, setter = { key, value -> setBoolean(key, value) })

fun PersistedObject.string(default: String) =
    PersistedDelegate(getter = { key -> getString(key) ?: default }, setter = { key, value -> setString(key, value) })

fun PersistedObject.int(default: Int) =
    PersistedDelegate(getter = { key -> getInteger(key) ?: default }, setter = { key, value -> setInteger(key, value) })

fun PersistedObject.stringList(default: String) =
    PersistedDelegate(getter = { key -> getString(key) ?: default }, setter = { key, value -> setString(key, value) })

class PersistedDelegate<T>(
    private val getter: (name: String) -> T, private val setter: (name: String, value: T) -> Unit
) : ReadWriteProperty<Any, T> {
    override fun getValue(thisRef: Any, property: KProperty<*>) = getter(property.name)
    override fun setValue(thisRef: Any, property: KProperty<*>, value: T) = setter(property.name, value)
}

class ListenerRegistration(listener: () -> Unit) {
    val listener: WeakReference<() -> Unit> = WeakReference(listener)
}

fun interface ListenerHandle {
    fun remove()
}

internal class LocalBearerTokenPersistenceException(message: String, cause: Throwable? = null) :
    IllegalStateException(message, cause)

/**
 * Owns the installation-scoped loopback credential.
 *
 * Burp's extension data belongs to the current project and is memory-only when no project file is open. It is used
 * here only as a one-time migration source. Preferences are authoritative because the Montoya contract guarantees that
 * they survive extension and Burp reloads.
 */
private class InstallationBearerTokenStore(
    private val preferences: Preferences,
    private val legacyProjectStorage: PersistedObject,
    private val logging: Logging,
) {
    fun current(): String = synchronized(INSTALLATION_BEARER_TOKEN_LOCK) {
        loadOrCreateLocked()
    }

    private fun loadOrCreateLocked(): String {
        val preferred = readPreference()
        val selected = when {
            preferred == null -> {
                val legacy = readLegacyProjectToken()
                val candidate = when {
                    legacy == null -> generateLocalBearerToken()
                    isValidLocalBearerToken(legacy) -> legacy
                    else -> throw LocalBearerTokenPersistenceException(
                        "The legacy local MCP bearer token is invalid; rotate it explicitly"
                    )
                }
                persistPreference(candidate)
            }
            isValidLocalBearerToken(preferred) -> preferred
            else -> throw LocalBearerTokenPersistenceException(
                "The installation-scoped local MCP bearer token is invalid; rotate it explicitly"
            )
        }

        removeLegacyProjectToken()
        return selected
    }

    fun rotate(): String = synchronized(INSTALLATION_BEARER_TOKEN_LOCK) {
        val replacement = persistPreference(generateLocalBearerToken())
        removeLegacyProjectToken()
        replacement
    }

    private fun readPreference(): String? = try {
        preferences.getString(INSTALLATION_BEARER_TOKEN_KEY)
    } catch (e: CancellationException) {
        throw e
    } catch (e: Exception) {
        throw LocalBearerTokenPersistenceException(
            "Unable to read the installation-scoped local MCP bearer token",
            e,
        )
    }

    private fun readLegacyProjectToken(): String? = try {
        legacyProjectStorage.getString(LEGACY_PROJECT_BEARER_TOKEN_KEY)
    } catch (e: CancellationException) {
        throw e
    } catch (e: Exception) {
        throw LocalBearerTokenPersistenceException(
            "Unable to inspect the legacy project-scoped local MCP bearer token",
            e,
        )
    }

    private fun persistPreference(token: String): String {
        try {
            preferences.setString(INSTALLATION_BEARER_TOKEN_KEY, token)
        } catch (e: CancellationException) {
            throw e
        } catch (writeFailure: Exception) {
            val committed = readPreferenceAfterWrite()
            if (committed != token) {
                throw LocalBearerTokenPersistenceException(
                    "Unable to persist the installation-scoped local MCP bearer token",
                    writeFailure,
                )
            }
            return committed
        }

        val observed = readPreferenceAfterWrite()
            ?: return token // A successful Montoya setter is authoritative if a defensive reread is unavailable.
        if (observed != token) {
            throw LocalBearerTokenPersistenceException(
                "Unable to confirm the installation-scoped local MCP bearer token update"
            )
        }
        return token
    }

    private fun readPreferenceAfterWrite(): String? = try {
        preferences.getString(INSTALLATION_BEARER_TOKEN_KEY)
    } catch (e: CancellationException) {
        throw e
    } catch (_: Exception) {
        null
    }

    private fun removeLegacyProjectToken() {
        try {
            legacyProjectStorage.deleteString(LEGACY_PROJECT_BEARER_TOKEN_KEY)
        } catch (failure: Exception) {
            // The installation credential is already authoritative here. Cleanup cancellation or failure must not
            // overturn a committed migration/rotation or make an existing preference unavailable to this operation.
            try {
                logging.logToError(
                    "Failed to remove the obsolete project-scoped MCP credential: ${safeExceptionSummary(failure)}"
                )
            } catch (_: Exception) {
                // A logging failure must not invalidate an already committed installation credential.
            }
        }
    }
}

private fun generateLocalBearerToken(): String {
    val bytes = ByteArray(32)
    SecureRandom().nextBytes(bytes)
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
}

private fun normalizeTargetList(raw: String): List<String> {
    if (raw.isBlank()) return emptyList()
    return raw.split(TARGET_SEPARATOR)
        .mapNotNull { TargetValidation.normalizeTarget(it.trim()) }
        .distinct()
}