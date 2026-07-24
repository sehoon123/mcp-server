package net.portswigger.mcp.tools

import kotlinx.coroutines.CancellationException
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class OperationOutcomePolicyTest {
    @Test
    fun `uncertain execution guidance is bounded redacted and single line`() {
        val token = "A".repeat(43)
        val result = uncertainExecutionError(
            " Scope update may have been partially applied\r\n",
            IllegalStateException("Authorization: Bearer $token at /home/user/private.json\n" + "x".repeat(1_000)),
        )

        assertTrue(result.startsWith("Scope update may have been partially applied;"))
        assertTrue(result.contains(UNCERTAIN_RETRY_GUIDANCE))
        assertTrue(result.length <= MAX_OPERATION_OUTCOME_ERROR_CHARS)
        assertFalse(result.any(Char::isISOControl))
        assertFalse(result.contains(token))
        assertFalse(result.contains("/home/user/private.json"))

        val sensitiveSummary = uncertainExecutionError("token=$token at /home/user/private.json may have changed")
        assertFalse(sensitiveSummary.contains(token))
        assertFalse(sensitiveSummary.contains("/home/user/private.json"))
    }

    @Test
    fun `uncertain execution guidance honors smaller result bounds and survives a long summary`() {
        val result = uncertainExecutionError("Operation may have completed", maxChars = 64)
        val longSummary = uncertainExecutionError("x".repeat(1_000), maxChars = MAX_STANDARD_TOOL_ERROR_CHARS)

        assertEquals(64, result.length)
        assertTrue(result.startsWith("Operation may have completed; do not retry"))
        assertTrue(longSummary.contains(UNCERTAIN_RETRY_GUIDANCE))
        assertTrue(longSummary.length <= MAX_STANDARD_TOOL_ERROR_CHARS)
    }

    @Test
    fun `result probing and uncertain formatting preserve cancellation`() {
        assertFailsWith<CancellationException> {
            runCatchingPreservingCancellation<Unit> { throw CancellationException("cancelled") }
        }
        assertFailsWith<CancellationException> {
            uncertainExecutionError("Operation may have completed", CancellationException("cancelled"))
        }

        val failure = runCatchingPreservingCancellation<Unit> { error("unavailable") }.exceptionOrNull()
        assertTrue(failure is IllegalStateException)
    }
}
