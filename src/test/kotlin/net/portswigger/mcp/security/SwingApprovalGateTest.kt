package net.portswigger.mcp.security

import io.mockk.*
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.yield
import org.junit.jupiter.api.Test
import javax.swing.SwingUtilities
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse

class SwingApprovalGateTest {
    @Test
    fun `approval dialogs are queued one at a time`() = runBlocking {
        val queued = mutableListOf<Runnable>()
        mockkStatic(SwingUtilities::class)
        try {
            every { SwingUtilities.invokeLater(capture(queued)) } returns Unit

            val first = async(start = CoroutineStart.UNDISPATCHED) { SwingApprovalGate.showOption { 1 } }
            val second = async(start = CoroutineStart.UNDISPATCHED) { SwingApprovalGate.showOption { 2 } }

            assertEquals(1, queued.size)
            assertFalse(second.isCompleted)
            queued.removeFirst().run()
            assertEquals(1, first.await())
            yield()

            assertEquals(1, queued.size)
            queued.removeFirst().run()
            assertEquals(2, second.await())
        } finally {
            unmockkStatic(SwingUtilities::class)
        }
    }

    @Test
    fun `dialog exception releases the gate for the next approval`() = runBlocking {
        val queued = mutableListOf<Runnable>()
        mockkStatic(SwingUtilities::class)
        try {
            every { SwingUtilities.invokeLater(capture(queued)) } returns Unit

            val first = async(start = CoroutineStart.UNDISPATCHED) {
                runCatching { SwingApprovalGate.showOption { throw IllegalStateException("dialog failed") } }
            }
            val second = async(start = CoroutineStart.UNDISPATCHED) { SwingApprovalGate.showOption { 2 } }

            assertEquals(1, queued.size)
            assertFalse(second.isCompleted)
            queued.removeFirst().run()
            assertFailsWith<IllegalStateException> { first.await().getOrThrow() }
            yield()

            assertEquals(1, queued.size)
            queued.removeFirst().run()
            assertEquals(2, second.await())
        } finally {
            unmockkStatic(SwingUtilities::class)
        }
    }

    @Test
    fun `dialog error releases the gate for the next approval`() = runBlocking {
        val queued = mutableListOf<Runnable>()
        mockkStatic(SwingUtilities::class)
        try {
            every { SwingUtilities.invokeLater(capture(queued)) } returns Unit

            val first = async(start = CoroutineStart.UNDISPATCHED) {
                runCatching { SwingApprovalGate.showOption { throw AssertionError("dialog failed") } }
            }
            val second = async(start = CoroutineStart.UNDISPATCHED) { SwingApprovalGate.showOption { 2 } }

            assertEquals(1, queued.size)
            assertFalse(second.isCompleted)
            assertFailsWith<AssertionError> { queued.removeFirst().run() }
            assertFailsWith<AssertionError> { first.await().getOrThrow() }
            yield()

            assertEquals(1, queued.size)
            queued.removeFirst().run()
            assertEquals(2, second.await())
        } finally {
            unmockkStatic(SwingUtilities::class)
        }
    }
}
