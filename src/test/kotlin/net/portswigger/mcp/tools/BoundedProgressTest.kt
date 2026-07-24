package net.portswigger.mcp.tools

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class BoundedProgressTest {
    @Test
    fun `fixed stages are monotonic deduplicated and bounded`() = runBlocking {
        val events = mutableListOf<Triple<Double, Double?, String?>>()
        val progress = FixedStageProgress(
            listOf("validate", "scan", "complete"),
        ) { value, total, message -> events += Triple(value, total, message) }

        progress.report(0)
        progress.report(0)
        progress.report(2)
        progress.report(1)
        progress.report(2)

        assertEquals(
            listOf<Triple<Double, Double?, String?>>(
                Triple(0.0, 2.0, "validate"),
                Triple(2.0, 2.0, "complete"),
            ),
            events,
        )
    }

    @Test
    fun `ordinary delivery failure is optional and the failed stage is not retried`() = runBlocking {
        val attempts = mutableListOf<Double>()
        val delivered = mutableListOf<Double>()
        val progress = FixedStageProgress(listOf("start", "complete")) { value, _, _ ->
            attempts += value
            if (value == 0.0) throw IllegalStateException("stream disconnected")
            delivered += value
        }

        progress.report(0)
        progress.report(0)
        progress.report(1)

        assertEquals(listOf(0.0, 1.0), attempts)
        assertEquals(listOf(1.0), delivered)
    }

    @Test
    fun `progress cancellation is never converted into optional notification failure`() = runBlocking {
        val progress = FixedStageProgress(listOf("start", "complete")) { _, _, _ ->
            throw CancellationException("client cancelled")
        }

        assertFailsWith<CancellationException> { progress.report(0) }
        Unit
    }

    @Test
    fun `invalid progress definitions fail before work starts`() {
        assertFailsWith<IllegalArgumentException> {
            FixedStageProgress(listOf("only"), NO_TOOL_PROGRESS_REPORTER)
        }
        assertFailsWith<IllegalArgumentException> {
            FixedStageProgress(listOf("valid", "x".repeat(129)), NO_TOOL_PROGRESS_REPORTER)
        }
    }
}
