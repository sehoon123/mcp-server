package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.BurpSuiteEdition
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import net.portswigger.mcp.presets.WorkflowPresetStore
import java.util.concurrent.Semaphore
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

private const val PROJECT_BOUNDARY_RESET_ADMISSION_MILLIS = 50L
private const val PROJECT_BOUNDARY_CLOSE_WAIT_MILLIS = 2_000L

internal class OrganizerMutationNotStartedException(cause: Exception) :
    IllegalStateException("Organizer mutation did not start", cause)

private data class InitializedToolServices(
    val scannerAudits: ScannerAuditService?,
    val collaborator: CollaboratorToolService?,
    val httpMetadataIndex: HttpMetadataIndex?,
)

/** Extension-lifetime state that must survive MCP HTTP server restarts. */
internal class ToolServices(
    private val api: MontoyaApi,
    val workflowPresetStore: WorkflowPresetStore,
    private val projectBoundaryCloseWaitMillis: Long = PROJECT_BOUNDARY_CLOSE_WAIT_MILLIS,
) {
    val historyPerformanceDiagnostics = HistoryPerformanceDiagnostics()
    private val metadataChangeSignals = MetadataChangeSignals()
    private val metadataEventBridge = MontoyaMetadataEventBridge(api, metadataChangeSignals)
    private val collaboratorDelegate = lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
        CollaboratorToolService(api)
    }
    private val scannerAuditsDelegate = lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
        ScannerAuditService(api)
    }
    private val httpMetadataIndexDelegate = lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
        HttpMetadataIndex(
            api,
            performanceDiagnostics = historyPerformanceDiagnostics,
            changeSignals = metadataChangeSignals,
        )
    }
    private val httpSessionSecurityAnalyzerDelegate = lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
        HttpSessionSecurityAnalyzerService(api)
    }
    private val lifecycleLock = Any()
    private val projectBoundaryResetPermit = Semaphore(1, true)
    private val closed = AtomicBoolean()
    private val closeClaimed = AtomicBoolean()

    init {
        require(projectBoundaryCloseWaitMillis in 1..PROJECT_BOUNDARY_CLOSE_WAIT_MILLIS) {
            "Project-boundary close wait is out of range"
        }
    }

    val collaborator: CollaboratorToolService get() = openService(collaboratorDelegate)
    val scannerAudits: ScannerAuditService get() = openService(scannerAuditsDelegate)
    val httpMetadataIndex: HttpMetadataIndex get() = openService(httpMetadataIndexDelegate)
    val httpSessionSecurityAnalyzer: HttpSessionSecurityAnalyzerService
        get() = openService(httpSessionSecurityAnalyzerDelegate)

    private fun <T> openService(delegate: Lazy<T>): T = synchronized(lifecycleLock) {
        check(!closed.get()) { "MCP tool services are closed" }
        delegate.value
    }

    fun performanceSnapshot(): HistoryPerformanceSnapshot = historyPerformanceDiagnostics.snapshot()

    suspend fun withOrganizerMutation(block: suspend () -> Unit) {
        var started = false
        try {
            httpMetadataIndex.withMutation {
                started = true
                block()
            }
        } catch (failure: CancellationException) {
            throw failure
        } catch (failure: Exception) {
            if (!started) throw OrganizerMutationNotStartedException(failure)
            throw failure
        }
    }

    suspend fun resetForProjectBoundary() {
        val coroutineContext = currentCoroutineContext()
        coroutineContext.ensureActive()
        while (!projectBoundaryResetPermit.tryAcquire(PROJECT_BOUNDARY_RESET_ADMISSION_MILLIS, TimeUnit.MILLISECONDS)) {
            coroutineContext.ensureActive()
        }
        try {
            coroutineContext.ensureActive()
            if (closed.get()) return
            val hasProfessionalState = scannerAuditsDelegate.isInitialized() || collaboratorDelegate.isInitialized()
            val isProfessional = if (hasProfessionalState) {
                val edition = api.burpSuite().version().edition()
                coroutineContext.ensureActive()
                if (closed.get()) return
                edition == BurpSuiteEdition.PROFESSIONAL
            } else {
                false
            }
            if (isProfessional && scannerAuditsDelegate.isInitialized()) {
                scannerAuditsDelegate.value.resetForProjectBoundary()
                coroutineContext.ensureActive()
                if (closed.get()) return
            }
            if (isProfessional && collaboratorDelegate.isInitialized()) {
                collaboratorDelegate.value.resetForProjectBoundary()
                coroutineContext.ensureActive()
                if (closed.get()) return
            }
            if (httpMetadataIndexDelegate.isInitialized()) httpMetadataIndexDelegate.value.resetForProjectBoundary()
        } finally {
            projectBoundaryResetPermit.release()
            if (closed.get()) finishDeferredClose()
        }
    }

    fun close() {
        closed.set(true)
        tombstoneInitializedIndex()
        var interrupted = false
        val acquired = try {
            projectBoundaryResetPermit.tryAcquire(projectBoundaryCloseWaitMillis, TimeUnit.MILLISECONDS)
        } catch (_: InterruptedException) {
            interrupted = true
            projectBoundaryResetPermit.tryAcquire()
        }
        if (acquired) {
            val initialized = try {
                claimInitializedServices()
            } finally {
                projectBoundaryResetPermit.release()
            }
            initialized?.let(::closeInitializedServices)
        }
        if (interrupted) Thread.currentThread().interrupt()
    }

    private fun tombstoneInitializedIndex() = synchronized(lifecycleLock) {
        if (httpMetadataIndexDelegate.isInitialized()) httpMetadataIndexDelegate.value.requestClose()
    }

    private fun finishDeferredClose() {
        if (!projectBoundaryResetPermit.tryAcquire()) return
        val initialized = try {
            claimInitializedServices()
        } finally {
            projectBoundaryResetPermit.release()
        }
        initialized?.let(::closeInitializedServices)
    }

    private fun claimInitializedServices(): InitializedToolServices? {
        if (!closeClaimed.compareAndSet(false, true)) return null
        return synchronized(lifecycleLock) {
            InitializedToolServices(
                scannerAudits = if (scannerAuditsDelegate.isInitialized()) scannerAuditsDelegate.value else null,
                collaborator = if (collaboratorDelegate.isInitialized()) collaboratorDelegate.value else null,
                httpMetadataIndex = if (httpMetadataIndexDelegate.isInitialized()) {
                    httpMetadataIndexDelegate.value
                } else {
                    null
                },
            )
        }
    }

    private fun closeInitializedServices(initialized: InitializedToolServices) {
        initialized.httpMetadataIndex?.requestClose()
        val cleanupThread = Thread({
            runCatching(metadataEventBridge::close)
            initialized.scannerAudits?.let { runCatching(it::close) }
            initialized.collaborator?.let { runCatching(it::close) }
            runCatching(metadataChangeSignals::close)
            initialized.httpMetadataIndex?.let { runCatching(it::close) }
        }, "independent-mcp-tool-service-cleanup").apply {
            isDaemon = true
            start()
        }
        try {
            cleanupThread.join(projectBoundaryCloseWaitMillis)
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
        }
    }
}
