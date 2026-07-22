package net.portswigger.mcp.security

import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import net.portswigger.mcp.config.Dialogs
import javax.swing.SwingUtilities

/** Serializes all security approval modals and disposes the active modal when its MCP call is cancelled. */
internal object SwingApprovalGate {
    private val mutex = Mutex()

    suspend fun showOption(showDialog: () -> Int): Int = mutex.withLock {
        suspendCancellableCoroutine { continuation ->
            continuation.invokeOnCancellation {
                // Posting unconditionally closes the race where cancellation occurs between the EDT's active check
                // and making the modal visible. The modal event loop continues processing this queued disposal.
                SwingUtilities.invokeLater { Dialogs.dismissActiveOptionDialog() }
            }
            SwingUtilities.invokeLater ui@{
                if (!continuation.isActive) return@ui
                val result = showDialog()
                if (continuation.isActive) continuation.resume(result) { _, _, _ -> }
            }
        }
    }
}
