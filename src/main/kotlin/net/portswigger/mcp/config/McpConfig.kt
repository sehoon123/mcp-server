package net.portswigger.mcp.config

import burp.api.montoya.logging.Logging
import burp.api.montoya.persistence.PersistedObject
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
private const val LOCAL_BEARER_TOKEN_KEY = "localBearerToken"
private const val AUDIT_RETENTION_ENTRIES_KEY = "auditRetentionEntries"
private val LOCAL_BEARER_TOKEN_PATTERN = Regex("[A-Za-z0-9_-]{43,128}")

class McpConfig(private val storage: PersistedObject, private val logging: Logging) {

    var enabled by storage.boolean(true)
    var configEditingTooling by storage.boolean(false)
    var host by storage.string("127.0.0.1")
    var port by storage.int(9876)
    var requireHttpRequestApproval by storage.boolean(true)
    var requireRequestActionApproval: Boolean
        get() = storage.getBoolean("requireRequestActionApproval") ?: true
        set(value) {
            val previous = requireRequestActionApproval
            storage.setBoolean("requireRequestActionApproval", value)
            if (previous != value) notifyRequestActionApprovalChanged()
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

    @Volatile
    private var cachedLocalBearerToken: String? = null

    /** Per-installation credential used only by the loopback MCP HTTP endpoint. */
    val localBearerToken: String
        get() = cachedLocalBearerToken ?: loadOrCreateLocalBearerToken()

    @Synchronized
    private fun loadOrCreateLocalBearerToken(): String {
        cachedLocalBearerToken?.let { return it }
        val persisted = storage.getString(LOCAL_BEARER_TOKEN_KEY)
        val token = persisted?.takeIf(LOCAL_BEARER_TOKEN_PATTERN::matches) ?: generateLocalBearerToken().also {
            storage.setString(LOCAL_BEARER_TOKEN_KEY, it)
        }
        cachedLocalBearerToken = token
        return token
    }

    @Synchronized
    fun rotateLocalBearerToken(): String {
        val token = generateLocalBearerToken()
        storage.setString(LOCAL_BEARER_TOKEN_KEY, token)
        cachedLocalBearerToken = token
        return token
    }

    private var _autoApproveTargets by storage.stringList("")
    @Volatile
    private var cachedTargetsRaw: String? = null
    @Volatile
    private var cachedTargets: List<String> = emptyList()
    private val targetsChangeListeners = CopyOnWriteArrayList<ListenerRegistration>()
    private val dataAccessChangeListeners = CopyOnWriteArrayList<ListenerRegistration>()
    private val requestActionApprovalChangeListeners = CopyOnWriteArrayList<ListenerRegistration>()

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

    private fun cleanupStaleListeners(listenerList: CopyOnWriteArrayList<ListenerRegistration>) {
        val staleListeners = listenerList.filter { it.listener.get() == null }
        listenerList.removeAll(staleListeners)
    }

    fun cleanup() {
        targetsChangeListeners.clear()
        dataAccessChangeListeners.clear()
        requestActionApprovalChangeListeners.clear()
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