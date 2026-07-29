package net.portswigger.mcp.tools

import kotlinx.coroutines.CancellationException
import net.portswigger.mcp.security.safeExceptionSummary
import net.portswigger.mcp.security.safeSingleLine

internal const val MAX_OPERATION_OUTCOME_ERROR_CHARS = 512
internal const val UNCERTAIN_RETRY_GUIDANCE =
    "do not retry automatically; reconcile Burp state before another attempt"

private const val MAX_UNCERTAIN_SUMMARY_CHARS = 256
private val OUTCOME_ERROR_WHITESPACE = Regex("[\\s\\p{Cc}]+")

/**
 * Produces the common fail-closed message for a side effect whose final state cannot be proved.
 *
 * Existing tool schemas keep their family-specific status and execution-state enums. This helper keeps the
 * non-retryable reconciliation policy identical across those schemas. Cancellation is preserved by default; a caller
 * that has already crossed a side-effect boundary must explicitly disable preservation and report uncertainty.
 */
internal fun uncertainExecutionError(
    summary: String,
    error: Throwable? = null,
    maxChars: Int = MAX_OPERATION_OUTCOME_ERROR_CHARS,
    preserveCancellation: Boolean = true,
): String {
    require(summary.isNotBlank()) { "uncertain execution summary must not be blank" }
    val requiredChars = UNCERTAIN_RETRY_GUIDANCE.length + 3
    require(maxChars >= requiredChars) {
        "uncertain execution error bound must leave room for retry guidance"
    }
    if (preserveCancellation && error is CancellationException) throw error

    val summaryLimit = minOf(maxChars - UNCERTAIN_RETRY_GUIDANCE.length - 2, MAX_UNCERTAIN_SUMMARY_CHARS)
    val normalizedSummary = safeSingleLine(summary, limit = summaryLimit).trimEnd('.', ';', ':')
    val required = "$normalizedSummary; $UNCERTAIN_RETRY_GUIDANCE"
        .replace(OUTCOME_ERROR_WHITESPACE, " ")
        .trim()
    if (error == null) return required
    return (required + ": ${safeExceptionSummary(error)}").take(maxChars)
}

/** Kotlin's standard runCatching catches cancellation; result probing in suspend operations must not. */
internal fun <T> runCatchingPreservingCancellation(block: () -> T): Result<T> = try {
    Result.success(block())
} catch (e: CancellationException) {
    throw e
} catch (t: Throwable) {
    Result.failure(t)
}
