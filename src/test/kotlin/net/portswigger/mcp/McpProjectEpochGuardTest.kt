package net.portswigger.mcp

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.yield
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse

class McpProjectEpochGuardTest {
    @Test
    fun `stable project does not reset sessions and transition resets before it is accepted`() = runBlocking {
        var projectId = "project-one"
        var resets = 0
        val guard = McpProjectEpochGuard({ projectId }) { resets++ }

        assertEquals(McpProjectBindingStatus.READY, guard.align())
        assertEquals(McpProjectBindingStatus.READY, guard.align())
        assertEquals(0, resets)

        projectId = "project-two"
        assertEquals(McpProjectBindingStatus.TRANSITIONED, guard.align())
        assertEquals(1, resets)
        assertEquals(McpProjectBindingStatus.READY, guard.align())
        assertEquals(1, resets)
    }

    @Test
    fun `invalid or unavailable project binding fails closed and resets an established epoch once`() = runBlocking {
        var projectId = "project-one"
        var fail = false
        var resets = 0
        val guard = McpProjectEpochGuard(
            projectIdProvider = {
                if (fail) error("project unavailable")
                projectId
            },
            resetSessions = { resets++ },
        )

        assertEquals(McpProjectBindingStatus.READY, guard.align())
        projectId = "\u0000invalid"
        assertEquals(McpProjectBindingStatus.UNAVAILABLE, guard.align())
        assertEquals(1, resets)
        assertEquals(McpProjectBindingStatus.UNAVAILABLE, guard.align())
        assertEquals(1, resets)

        projectId = "project-two"
        assertEquals(McpProjectBindingStatus.READY, guard.align())
        fail = true
        assertEquals(McpProjectBindingStatus.UNAVAILABLE, guard.align())
        assertEquals(2, resets)
    }

    @Test
    fun `new project admission waits for stale session cleanup`() = runBlocking {
        var projectId = "project-one"
        val resetStarted = CompletableDeferred<Unit>()
        val releaseReset = CompletableDeferred<Unit>()
        val guard = McpProjectEpochGuard(
            projectIdProvider = { projectId },
            resetSessions = {
                resetStarted.complete(Unit)
                releaseReset.await()
            },
        )
        assertEquals(McpProjectBindingStatus.READY, guard.align())
        projectId = "project-two"

        val transition = async { guard.align() }
        resetStarted.await()
        val concurrentAdmission = async { guard.align() }
        yield()
        assertFalse(concurrentAdmission.isCompleted)

        releaseReset.complete(Unit)
        assertEquals(McpProjectBindingStatus.TRANSITIONED, transition.await())
        assertEquals(McpProjectBindingStatus.READY, concurrentAdmission.await())
    }

    @Test
    fun `project observation preserves coroutine cancellation`() = runBlocking {
        val guard = McpProjectEpochGuard(
            projectIdProvider = { throw CancellationException("cancelled") },
            resetSessions = {},
        )

        assertFailsWith<CancellationException> { guard.align() }
        Unit
    }
}
