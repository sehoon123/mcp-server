package net.portswigger.mcp.security

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class SessionApprovalSecurityTest {
    @Test
    fun `registry is bounded session isolated and stores only fixed category grants`() = runBlocking {
        val registry = McpSessionApprovalRegistry(maxSessions = 2)

        assertTrue(registry.activate("session-a"))
        assertTrue(registry.activate("session-b"))
        assertFalse(registry.activate("session-a"))
        assertFalse(registry.activate("session-c"))
        assertFalse(registry.activate("bad\u0000session"))

        val first = assertNotNull(registry.contextFor("session-a"))
        val second = assertNotNull(registry.contextFor("session-b"))
        withContext(first) {
            assertTrue(grantCurrentSessionApproval(McpSessionApproval.OUTBOUND_HTTP))
            assertTrue(grantCurrentSessionApproval(McpSessionApproval.SITE_MAP))
        }
        withContext(second) {
            assertTrue(grantCurrentSessionApproval(McpSessionApproval.REQUEST_ROUTING))
        }

        assertTrue(registry.isGranted("session-a", McpSessionApproval.OUTBOUND_HTTP))
        assertTrue(registry.isGranted("session-a", McpSessionApproval.SITE_MAP))
        assertFalse(registry.isGranted("session-a", McpSessionApproval.REQUEST_ROUTING))
        assertFalse(registry.isGranted("session-b", McpSessionApproval.OUTBOUND_HTTP))
        assertEquals(McpSessionApprovalSummary(2, 3), registry.summary())

        assertEquals(3, registry.clearApprovals())
        assertEquals(McpSessionApprovalSummary(0, 0), registry.summary())
        withContext(first) {
            assertTrue(isCurrentSessionApproved(McpSessionApproval.OUTBOUND_HTTP))
        }
        withContext(requireNotNull(registry.contextFor("session-a"))) {
            assertFalse(isCurrentSessionApproved(McpSessionApproval.OUTBOUND_HTTP))
        }

        registry.remove("session-a")
        assertNull(registry.contextFor("session-a"))
        assertTrue(registry.activate("session-c"))
        registry.clearSessions()
        assertEquals(McpSessionApprovalSummary(0, 0), registry.summary())
    }

    @Test
    fun `server session aliases are one to one bounded and cannot collide with primary IDs`() = runBlocking {
        val registry = McpSessionApprovalRegistry(maxSessions = 2)
        assertTrue(registry.activate("primary-a"))
        assertTrue(registry.attachServerSession("primary-a", "primary-a"))
        assertTrue(registry.attachServerSession("primary-a", "sdk-a"))
        assertTrue(registry.attachServerSession("primary-a", "sdk-a"))
        assertFalse(registry.attachServerSession("primary-a", "sdk-a-second"))
        assertFalse(registry.activate("sdk-a"))

        withContext(assertNotNull(registry.contextFor("sdk-a"))) {
            assertTrue(grantCurrentSessionApproval(McpSessionApproval.OUTBOUND_HTTP))
        }
        assertTrue(registry.isGranted("primary-a", McpSessionApproval.OUTBOUND_HTTP))

        assertTrue(registry.activate("primary-b"))
        assertFalse(registry.attachServerSession("primary-b", "sdk-a"))
        assertTrue(registry.attachServerSession("primary-b", "sdk-b"))

        registry.remove("primary-a")
        assertNull(registry.contextFor("sdk-a"))
        assertTrue(registry.activate("sdk-a"))
    }

    @Test
    fun `approval categories remain independent within one session`() = runBlocking {
        val registry = McpSessionApprovalRegistry(maxSessions = 1)
        assertTrue(registry.activate("isolated-session"))
        val context = assertNotNull(registry.contextFor("isolated-session"))

        withContext(context) {
            grantCurrentSessionApproval(McpSessionApproval.REQUEST_ROUTING)
            grantCurrentSessionApproval(McpSessionApproval.HTTP_HISTORY)

            assertTrue(isCurrentSessionApproved(McpSessionApproval.REQUEST_ROUTING))
            assertTrue(isCurrentSessionApproved(McpSessionApproval.HTTP_HISTORY))
            assertFalse(isCurrentSessionApproved(McpSessionApproval.OUTBOUND_HTTP))
            assertFalse(isCurrentSessionApproved(McpSessionApproval.SCOPE_CHANGES))
            assertFalse(isCurrentSessionApproved(McpSessionApproval.SITE_MAP))
        }
    }

    @Test
    fun `invocation sees only grants snapshotted at start or explicitly added by itself`() = runBlocking {
        val registry = McpSessionApprovalRegistry(maxSessions = 1)
        assertTrue(registry.activate("snapshot-session"))
        val earlierInvocation = assertNotNull(registry.contextFor("snapshot-session"))
        val grantingInvocation = assertNotNull(registry.contextFor("snapshot-session"))

        withContext(grantingInvocation) {
            assertTrue(grantCurrentSessionApproval(McpSessionApproval.SITE_MAP))
            assertTrue(isCurrentSessionApproved(McpSessionApproval.SITE_MAP))
        }
        withContext(earlierInvocation) {
            assertFalse(isCurrentSessionApproved(McpSessionApproval.SITE_MAP))
        }
        withContext(assertNotNull(registry.contextFor("snapshot-session"))) {
            assertTrue(isCurrentSessionApproved(McpSessionApproval.SITE_MAP))
        }
    }

    @Test
    fun `reset does not cancel work that was already authorized and started`() = runBlocking {
        val registry = McpSessionApprovalRegistry(maxSessions = 1)
        assertTrue(registry.activate("in-flight-session"))
        val context = assertNotNull(registry.contextFor("in-flight-session"))
        withContext(context) { grantCurrentSessionApproval(McpSessionApproval.SCOPE_CHANGES) }
        val started = CompletableDeferred<Unit>()
        val finish = CompletableDeferred<Unit>()
        var sideEffectCompleted = false

        val operation = async {
            withContext(context) {
                assertTrue(isCurrentSessionApproved(McpSessionApproval.SCOPE_CHANGES))
                started.complete(Unit)
                finish.await()
                assertTrue(isCurrentSessionApproved(McpSessionApproval.SCOPE_CHANGES))
                sideEffectCompleted = true
            }
        }
        started.await()
        assertEquals(1, registry.clearApprovals())
        finish.complete(Unit)
        operation.await()

        assertTrue(sideEffectCompleted)
        assertEquals(McpSessionApprovalSummary(0, 0), registry.summary())
    }

    @Test
    fun `session grant outside an active MCP session degrades to the current explicit approval only`() = runBlocking {
        assertFalse(grantCurrentSessionApproval(McpSessionApproval.OUTBOUND_HTTP))
        assertFalse(isCurrentSessionApproved(McpSessionApproval.OUTBOUND_HTTP))
    }
}
