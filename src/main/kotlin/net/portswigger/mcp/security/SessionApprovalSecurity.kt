package net.portswigger.mcp.security

import kotlinx.coroutines.currentCoroutineContext
import java.util.EnumSet
import java.util.concurrent.atomic.AtomicInteger
import kotlin.coroutines.AbstractCoroutineContextElement
import kotlin.coroutines.CoroutineContext

/** Fixed, value-free approval categories that can be granted only for one active MCP session. */
internal enum class McpSessionApproval {
    OUTBOUND_HTTP,
    REQUEST_ROUTING,
    SCOPE_CHANGES,
    HTTP_HISTORY,
    SITE_MAP,
    WEBSOCKET_HISTORY,
    ORGANIZER,
    SCANNER_ISSUES,
    COLLABORATOR_INTERACTIONS,
}

internal data class McpSessionApprovalSummary(
    val sessionsWithApprovals: Int,
    val approvalGrants: Int,
)

internal class McpSessionApprovalState(
    private val onGrantAdded: (firstGrant: Boolean) -> Unit,
    private val onGrantsCleared: (cleared: Int) -> Unit,
) {
    private val grants = EnumSet.noneOf(McpSessionApproval::class.java)
    private var active = true

    @Synchronized
    fun grant(approval: McpSessionApproval): Boolean {
        if (!active) return false
        val firstGrant = grants.isEmpty()
        if (grants.add(approval)) onGrantAdded(firstGrant)
        return true
    }

    @Synchronized
    fun isGranted(approval: McpSessionApproval): Boolean = active && approval in grants

    @Synchronized
    fun snapshot(): EnumSet<McpSessionApproval> = if (active) {
        EnumSet.copyOf(grants)
    } else {
        EnumSet.noneOf(McpSessionApproval::class.java)
    }

    @Synchronized
    fun clear(): Int {
        val cleared = grants.size
        grants.clear()
        if (cleared > 0) onGrantsCleared(cleared)
        return cleared
    }

    @Synchronized
    fun deactivate() {
        if (!active) return
        active = false
        val cleared = grants.size
        grants.clear()
        if (cleared > 0) onGrantsCleared(cleared)
    }
}

internal class McpSessionApprovalContext private constructor(
    private val state: McpSessionApprovalState,
    private val invocationGrants: EnumSet<McpSessionApproval>,
) : AbstractCoroutineContextElement(Key) {
    companion object Key : CoroutineContext.Key<McpSessionApprovalContext> {
        fun create(state: McpSessionApprovalState): McpSessionApprovalContext =
            McpSessionApprovalContext(state, state.snapshot())
    }

    @Synchronized
    fun grant(approval: McpSessionApproval): Boolean {
        if (!state.grant(approval)) return false
        invocationGrants.add(approval)
        return true
    }

    /** Live grants from concurrent calls are excluded; this invocation sees its start snapshot plus its own grant. */
    @Synchronized
    fun isGranted(approval: McpSessionApproval): Boolean = approval in invocationGrants
}

/**
 * Bounded session policy state. Keys mirror the protocol sessions already held by the HTTP session registry; values
 * contain only a fixed enum set and never retain targets, URLs, headers, bodies, project identifiers, or client data.
 */
internal class McpSessionApprovalRegistry(private val maxSessions: Int) {
    private val lock = Any()
    private val sessions = HashMap<String, McpSessionApprovalState>()
    private val serverSessionAliases = HashMap<String, McpSessionApprovalState>()
    private val sessionsWithApprovals = AtomicInteger()
    private val approvalGrants = AtomicInteger()

    init {
        require(maxSessions > 0) { "maxSessions must be positive" }
    }

    fun activate(sessionId: String): Boolean = synchronized(lock) {
        if (!isValidSessionId(sessionId) || sessions.containsKey(sessionId) ||
            serverSessionAliases.containsKey(sessionId) || sessions.size >= maxSessions
        ) {
            false
        } else {
            sessions[sessionId] = McpSessionApprovalState(
                onGrantAdded = { firstGrant ->
                    approvalGrants.incrementAndGet()
                    if (firstGrant) sessionsWithApprovals.incrementAndGet()
                },
                onGrantsCleared = { cleared ->
                    approvalGrants.addAndGet(-cleared)
                    sessionsWithApprovals.decrementAndGet()
                },
            )
            true
        }
    }

    fun attachServerSession(primarySessionId: String, serverSessionId: String): Boolean = synchronized(lock) {
        val state = sessions[primarySessionId] ?: return false
        if (serverSessionId == primarySessionId) return true
        if (!isValidSessionId(serverSessionId) || sessions.containsKey(serverSessionId)) return false
        val existing = serverSessionAliases[serverSessionId]
        when {
            existing === state -> true
            existing != null || serverSessionAliases.size >= maxSessions ||
                serverSessionAliases.values.any { it === state } -> false
            else -> {
                serverSessionAliases[serverSessionId] = state
                true
            }
        }
    }

    fun remove(sessionId: String) {
        synchronized(lock) {
            val state = sessions.remove(sessionId) ?: return
            serverSessionAliases.entries.removeIf { it.value === state }
            state.deactivate()
        }
    }

    fun contextFor(sessionId: String): McpSessionApprovalContext? = synchronized(lock) {
        (sessions[sessionId] ?: serverSessionAliases[sessionId])?.let(McpSessionApprovalContext::create)
    }

    fun isGranted(sessionId: String, approval: McpSessionApproval): Boolean = synchronized(lock) {
        (sessions[sessionId] ?: serverSessionAliases[sessionId])?.isGranted(approval) == true
    }

    /** Clears grants without removing active session registrations, so in-flight calls keep their lifecycle intact. */
    fun clearApprovals(): Int = synchronized(lock) {
        sessions.values.sumOf(McpSessionApprovalState::clear)
    }

    fun clearSessions() {
        synchronized(lock) {
            val removed = sessions.values.toList()
            sessions.clear()
            serverSessionAliases.clear()
            removed.forEach(McpSessionApprovalState::deactivate)
        }
    }

    fun summary(): McpSessionApprovalSummary = McpSessionApprovalSummary(
        sessionsWithApprovals = sessionsWithApprovals.get().coerceAtLeast(0),
        approvalGrants = approvalGrants.get().coerceAtLeast(0),
    )

    private fun isValidSessionId(sessionId: String): Boolean =
        sessionId.isNotBlank() && sessionId.length <= 128 && sessionId.none(Char::isISOControl)
}

internal suspend fun isCurrentSessionApproved(approval: McpSessionApproval): Boolean =
    currentCoroutineContext()[McpSessionApprovalContext]?.isGranted(approval) == true

internal suspend fun grantCurrentSessionApproval(approval: McpSessionApproval): Boolean {
    val context = currentCoroutineContext()[McpSessionApprovalContext]
    if (context == null) {
        recordCurrentToolApproval(approval.auditKind(), "session_unavailable")
        return false
    }
    if (!context.grant(approval)) {
        recordCurrentToolApproval(approval.auditKind(), "session_unavailable")
        return false
    }
    recordCurrentToolApproval(approval.auditKind(), "session_grant")
    return true
}

private fun McpSessionApproval.auditKind(): String = when (this) {
    McpSessionApproval.OUTBOUND_HTTP -> "http_request"
    McpSessionApproval.REQUEST_ROUTING -> "request_routing"
    McpSessionApproval.SCOPE_CHANGES -> "scope_change"
    McpSessionApproval.HTTP_HISTORY -> "data_access:http_history"
    McpSessionApproval.SITE_MAP -> "data_access:site_map"
    McpSessionApproval.WEBSOCKET_HISTORY -> "data_access:websocket_history"
    McpSessionApproval.ORGANIZER -> "data_access:organizer"
    McpSessionApproval.SCANNER_ISSUES -> "data_access:scanner_issues"
    McpSessionApproval.COLLABORATOR_INTERACTIONS -> "data_access:collaborator_interactions"
}
