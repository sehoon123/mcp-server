package net.portswigger.mcp.tools

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive

internal typealias ToolProgressReporter = suspend (progress: Double, total: Double?, message: String?) -> Unit

internal val NO_TOOL_PROGRESS_REPORTER: ToolProgressReporter = { _, _, _ -> }

/** Emits at most one monotonic notification for each operation-defined stage. */
internal class FixedStageProgress(
    stageMessages: List<String>,
    private val reporter: ToolProgressReporter,
) {
    private val messages = stageMessages.toList()
    private var lastReportedStage = -1

    init {
        require(messages.size >= 2) { "fixed progress requires at least two stages" }
        require(messages.all { it.isNotBlank() && it.length <= MAX_FIXED_PROGRESS_MESSAGE_CHARS }) {
            "fixed progress messages must be bounded and non-empty"
        }
    }

    suspend fun report(stage: Int) {
        require(stage in messages.indices) { "progress stage is out of range" }
        currentCoroutineContext().ensureActive()
        if (stage <= lastReportedStage) return
        try {
            reporter(stage.toDouble(), messages.lastIndex.toDouble(), messages[stage])
        } catch (e: CancellationException) {
            throw e
        } catch (_: Exception) {
            // Progress delivery is optional and must not change the operation result.
        }
        lastReportedStage = stage
    }

    private companion object {
        const val MAX_FIXED_PROGRESS_MESSAGE_CHARS = 128
    }
}
