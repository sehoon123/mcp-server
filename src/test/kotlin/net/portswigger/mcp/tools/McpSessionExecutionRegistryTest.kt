package net.portswigger.mcp.tools

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import org.junit.jupiter.api.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class McpSessionExecutionRegistryTest {
    @Test
    fun `transport termination cancels execution aliases and rejects late registration`() {
        val registry = McpSessionExecutionRegistry()
        registry.enableLifecycleTracking()
        assertTrue(registry.activateSession("transport-session", "execution-session"))
        val first = Job()
        val second = Job()
        registry.register("transport-session", first)
        registry.register("execution-session", second)

        registry.cancelSession("transport-session")

        assertTrue(first.isCancelled)
        assertTrue(second.isCancelled)
        val late = Job()
        assertFailsWith<CancellationException> { registry.register("execution-session", late) }
        assertTrue(late.isCancelled)
    }

    @Test
    fun `duplicate wrapper leases retain a shared Job until every lease closes`() {
        val registry = McpSessionExecutionRegistry()
        assertTrue(registry.activateSession("transport-session", "execution-session"))
        val shared = Job()
        val firstLease = registry.register("execution-session", shared)
        val secondLease = registry.register("execution-session", shared)

        firstLease.close()
        assertFalse(shared.isCancelled)
        registry.cancelSession("transport-session")

        assertTrue(shared.isCancelled)
        secondLease.close()
    }

    @Test
    fun `terminal cancellation cannot be undone by activation or registry use`() {
        val registry = McpSessionExecutionRegistry()
        assertTrue(registry.activateSession("transport-session", "execution-session"))
        val running = Job()
        registry.register("execution-session", running)

        registry.cancelAll()

        assertTrue(running.isCancelled)
        assertFalse(registry.activateSession("late-transport", "late-execution"))
        val late = Job()
        assertFailsWith<CancellationException> { registry.register("late-execution", late) }
        assertTrue(late.isCancelled)
    }
}
