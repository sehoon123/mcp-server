package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import io.mockk.slot
import io.mockk.verify
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.runBlocking
import net.portswigger.mcp.presets.DeleteWorkflowPreset
import net.portswigger.mcp.presets.ExecuteWorkflowPreset
import net.portswigger.mcp.presets.ListWorkflowPresets
import net.portswigger.mcp.presets.SaveWorkflowPreset
import net.portswigger.mcp.presets.SavedHttpComparison
import net.portswigger.mcp.presets.SavedHttpSearch
import net.portswigger.mcp.presets.SavedWebSocketSearch
import net.portswigger.mcp.presets.WorkflowPreset
import net.portswigger.mcp.presets.WorkflowPresetDefinition
import net.portswigger.mcp.presets.WorkflowPresetStatus
import net.portswigger.mcp.presets.WorkflowPresetStore
import net.portswigger.mcp.presets.WorkflowPresetStoreException
import net.portswigger.mcp.presets.WorkflowPresetStoreFailure
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.util.concurrent.atomic.AtomicInteger

class WorkflowPresetServiceTest {
    private val api = mockk<MontoyaApi>(relaxed = true)
    private val store = mockk<WorkflowPresetStore>()
    private val http = mockk<HttpMessageSearchService>()
    private val webSocket = mockk<WebSocketMessageSearchService>()
    private val comparison = mockk<HttpMessageComparisonService>()
    private val service = WorkflowPresetService(api, store, http, webSocket, comparison)

    @Test
    fun `invalid requested project IDs are invalid arguments before every storage operation`() = runBlocking {
        every { api.project().id() } returns "current"
        val invalidSave = service.save(saveInput(" "))
        assertEquals(WorkflowPresetStatus.INVALID_ARGUMENT, invalidSave.status)
        assertEquals(null, invalidSave.projectId)
        assertEquals(WorkflowPresetStatus.INVALID_ARGUMENT, service.list(ListWorkflowPresets("bad\nproject")).status)
        assertEquals(
            WorkflowPresetStatus.INVALID_ARGUMENT,
            service.delete(DeleteWorkflowPreset("x".repeat(257), "one")).status,
        )
        assertEquals(
            WorkflowPresetStatus.INVALID_ARGUMENT,
            service.execute(ExecuteWorkflowPreset("", "one"), NO_TOOL_PROGRESS_REPORTER).status,
        )
        verify(exactly = 0) { store.save(any(), any()) }
        verify(exactly = 0) { store.list() }
        verify(exactly = 0) { store.delete(any()) }
    }

    @Test
    fun `unavailable invalid and overlong current project IDs never authorize storage`() {
        every { api.project().id() } throws IllegalStateException("unavailable")
        assertEquals(WorkflowPresetStatus.BURP_ERROR, service.save(saveInput("requested")).status)
        verify(exactly = 0) { store.save(any(), any()) }

        every { api.project().id() } returns "bad\ncurrent"
        assertEquals(WorkflowPresetStatus.BURP_ERROR, service.save(saveInput("requested")).status)
        verify(exactly = 0) { store.save(any(), any()) }

        val requested = "p".repeat(256)
        every { api.project().id() } returns requested + "suffix"
        val overlong = service.save(saveInput(requested))
        assertEquals(WorkflowPresetStatus.BURP_ERROR, overlong.status)
        assertEquals(null, overlong.projectId)
        verify(exactly = 0) { store.save(any(), any()) }
    }

    @Test
    fun `project mismatch before storage does not touch store`() {
        every { api.project().id() } returns "current"
        val result = service.save(saveInput("requested"))
        assertEquals(WorkflowPresetStatus.PROJECT_MISMATCH, result.status)
        assertEquals("current", result.projectId)
        assertEquals(StandardExecutionState.NOT_STARTED, result.executionState)
        verify(exactly = 0) { store.save(any(), any()) }
    }

    @Test
    fun `project mismatch after storage discards list and delegated output`() = runBlocking {
        every { api.project().id() } returnsMany listOf("p", "other")
        every { store.list() } returns emptyList()
        val listed = service.list(ListWorkflowPresets("p"))
        assertEquals(WorkflowPresetStatus.PROJECT_MISMATCH, listed.status)
        assertTrue(listed.items.isEmpty())

        every { api.project().id() } returnsMany listOf("p", "p", "other")
        every { store.list() } returns listOf(preset("http", WorkflowPresetDefinition(httpSearch = SavedHttpSearch())))
        coEvery { http.search(any(), any()) } returns httpResult(HttpMessageSearchStatus.OK)
        val executed = service.execute(ExecuteWorkflowPreset("p", "http"), NO_TOOL_PROGRESS_REPORTER)
        assertEquals(WorkflowPresetStatus.PROJECT_MISMATCH, executed.status)
        assertEquals(null, executed.httpSearch)

        val checks = AtomicInteger()
        every { api.project().id() } answers {
            if (checks.getAndIncrement() == 0) "p" else throw IllegalStateException("unavailable")
        }
        every { store.list() } returns listOf(preset("hidden", WorkflowPresetDefinition(httpSearch = SavedHttpSearch())))
        val unavailable = service.list(ListWorkflowPresets("p"))
        assertEquals(WorkflowPresetStatus.BURP_ERROR, unavailable.status)
        assertTrue(unavailable.items.isEmpty())
        assertEquals(null, unavailable.projectId)
    }

    @Test
    fun `save and delete are uncertain after attempted write or project switch`() {
        every { api.project().id() } returns "p"
        every { store.save(any(), any()) } throws WorkflowPresetStoreException(
            WorkflowPresetStoreFailure.STORAGE, writeAttempted = true
        )
        val failed = service.save(saveInput("p"))
        assertEquals(StandardExecutionState.UNCERTAIN, failed.executionState)
        assertEquals(ToolRetryGuidance.DO_NOT_RETRY, failed.retry)

        every { store.save(any(), any()) } returns Pair(true, false)
        every { api.project().id() } returnsMany listOf("p", "other")
        val switched = service.save(saveInput("p"))
        assertEquals(WorkflowPresetStatus.PROJECT_MISMATCH, switched.status)
        assertEquals(StandardExecutionState.UNCERTAIN, switched.executionState)

        every { api.project().id() } returns "p"
        every { store.delete(any()) } throws WorkflowPresetStoreException(
            WorkflowPresetStoreFailure.STORAGE, writeAttempted = true
        )
        val deleted = service.delete(DeleteWorkflowPreset("p", "one"))
        assertEquals(StandardExecutionState.UNCERTAIN, deleted.executionState)
        assertEquals(ToolRetryGuidance.DO_NOT_RETRY, deleted.retry)

        val checks = AtomicInteger()
        every { api.project().id() } answers {
            if (checks.getAndIncrement() == 0) "p" else throw IllegalStateException("unavailable")
        }
        every { store.save(any(), any()) } returns Pair(true, false)
        val unavailableAfterWrite = service.save(saveInput("p"))
        assertEquals(WorkflowPresetStatus.BURP_ERROR, unavailableAfterWrite.status)
        assertEquals(StandardExecutionState.UNCERTAIN, unavailableAfterWrite.executionState)
        assertEquals(null, unavailableAfterWrite.projectId)
    }

    @Test
    fun `invalid stored envelopes are not marked safe to retry while ordinary prewrite IO is`() {
        every { api.project().id() } returns "p"
        listOf(
            WorkflowPresetStoreFailure.MALFORMED,
            WorkflowPresetStoreFailure.UNKNOWN_VERSION,
            WorkflowPresetStoreFailure.OVERSIZED,
        ).forEach { failure ->
            every { store.save(any(), any()) } throws WorkflowPresetStoreException(failure)
            val saved = service.save(saveInput("p"))
            assertEquals(WorkflowPresetStatus.BURP_ERROR, saved.status)
            assertEquals(ToolRetryGuidance.DO_NOT_RETRY, saved.retry)
            assertEquals(StandardExecutionState.NOT_STARTED, saved.executionState)
        }

        every { store.delete(any()) } throws WorkflowPresetStoreException(WorkflowPresetStoreFailure.UNKNOWN_VERSION)
        val deleted = service.delete(DeleteWorkflowPreset("p", "one"))
        assertEquals(ToolRetryGuidance.DO_NOT_RETRY, deleted.retry)
        assertEquals(StandardExecutionState.NOT_STARTED, deleted.executionState)

        every { store.save(any(), any()) } throws WorkflowPresetStoreException(WorkflowPresetStoreFailure.STORAGE)
        val ioFailure = service.save(saveInput("p"))
        assertEquals(ToolRetryGuidance.SAFE_TO_RETRY, ioFailure.retry)
        assertEquals(StandardExecutionState.NOT_STARTED, ioFailure.executionState)
    }

    @Test
    fun `post-write project check cancellation is uncertain only after a mutation`() {
        var projectReads = 0
        every { api.project().id() } answers {
            if (projectReads++ == 0) "p" else throw CancellationException("post-save")
        }
        every { store.save(any(), any()) } returns Pair(true, false)
        val saved = service.save(saveInput("p"))
        assertEquals(StandardExecutionState.UNCERTAIN, saved.executionState)
        assertEquals(ToolRetryGuidance.DO_NOT_RETRY, saved.retry)

        projectReads = 0
        every { api.project().id() } answers {
            if (projectReads++ == 0) "p" else throw CancellationException("post-delete")
        }
        every { store.delete(any()) } returns true
        val deleted = service.delete(net.portswigger.mcp.presets.DeleteWorkflowPreset("p", "one"))
        assertEquals(StandardExecutionState.UNCERTAIN, deleted.executionState)
        assertEquals(ToolRetryGuidance.DO_NOT_RETRY, deleted.retry)

        projectReads = 0
        every { api.project().id() } answers {
            if (projectReads++ == 0) "p" else throw CancellationException("post-noop-delete")
        }
        every { store.delete(any()) } returns false
        assertThrows(CancellationException::class.java) {
            service.delete(net.portswigger.mcp.presets.DeleteWorkflowPreset("p", "absent"))
        }
    }

    @Test
    fun `execute validates kind specific runtime arguments before delegation`() = runBlocking {
        every { api.project().id() } returns "p"
        every { store.list() } returns listOf(
            preset("search", WorkflowPresetDefinition(httpSearch = SavedHttpSearch())),
            preset("compare", WorkflowPresetDefinition(httpComparison = SavedHttpComparison())),
        )
        val searchWithRefs = service.execute(
            ExecuteWorkflowPreset("p", "search", refs = listOf(ref("1"), ref("2"))), NO_TOOL_PROGRESS_REPORTER
        )
        assertEquals(WorkflowPresetStatus.INVALID_ARGUMENT, searchWithRefs.status)
        val comparisonWithoutRefs = service.execute(
            ExecuteWorkflowPreset("p", "compare"), NO_TOOL_PROGRESS_REPORTER
        )
        assertEquals(WorkflowPresetStatus.INVALID_ARGUMENT, comparisonWithoutRefs.status)
        coVerify(exactly = 0) { http.search(any(), any()) }
        coVerify(exactly = 0) { comparison.compare(any()) }
    }

    @Test
    fun `HTTP execution maps saved and runtime fields relays progress and delegated status`() = runBlocking {
        every { api.project().id() } returns "p"
        every { store.list() } returns listOf(preset("HTTP", WorkflowPresetDefinition(httpSearch = SavedHttpSearch(
            sources = listOf(HttpMessageSource.ORGANIZER), host = "example.test", methods = listOf("GET"),
            newestFirst = false, defaultLimit = 7,
        ))))
        val captured = slot<SearchHttpMessages>()
        coEvery { http.search(capture(captured), any()) } coAnswers {
            secondArg<ToolProgressReporter>()(1.0, 2.0, "delegated")
            httpResult(HttpMessageSearchStatus.ACCESS_DENIED)
        }
        val progress = mutableListOf<String?>()
        val output = service.execute(ExecuteWorkflowPreset("p", "http", limit = 3, cursor = "runtime-cursor")) {
            _, _, message -> progress += message
        }
        assertEquals(WorkflowPresetStatus.OK, output.status)
        assertEquals(HttpMessageSearchStatus.ACCESS_DENIED, output.httpSearch?.status)
        assertFalse(output.delegatedSuccess())
        assertEquals(3, captured.captured.limit)
        assertEquals("runtime-cursor", captured.captured.cursor)
        assertEquals("example.test", captured.captured.host)
        assertEquals(listOf("delegated"), progress)
        verify(exactly = 1) { store.list() }
    }

    @Test
    fun `WebSocket and comparison execution map only safe saved plus runtime fields`() = runBlocking {
        every { api.project().id() } returns "p"
        every { store.list() } returns listOf(preset("ws", WorkflowPresetDefinition(webSocketSearch = SavedWebSocketSearch(
            direction = WebSocketSearchDirection.CLIENT_TO_SERVER, listenerPort = 8080, defaultLimit = 4,
        ))))
        val wsInput = slot<SearchWebsocketMessages>()
        coEvery { webSocket.search(capture(wsInput), any()) } returns SearchWebsocketMessagesResult(
            WebSocketSearchStatus.OK, "p"
        )
        val ws = service.execute(ExecuteWorkflowPreset("p", "ws", cursor = "runtime"), NO_TOOL_PROGRESS_REPORTER)
        assertTrue(ws.delegatedSuccess())
        assertEquals("runtime", wsInput.captured.cursor)
        assertEquals(4, wsInput.captured.limit)
        assertEquals(null, wsInput.captured.webSocketId)
        assertEquals(null, wsInput.captured.regex)

        every { store.list() } returns listOf(preset("cmp", WorkflowPresetDefinition(httpComparison = SavedHttpComparison(
            part = HttpComparisonPart.REQUEST_HEADERS, ignoreHeaders = listOf("date"),
        ))))
        val compareInput = slot<CompareHttpMessages>()
        coEvery { comparison.compare(capture(compareInput)) } returns comparisonResult()
        val refs = listOf(ref("1"), ref("2"))
        val compared = service.execute(ExecuteWorkflowPreset("p", "cmp", refs = refs), NO_TOOL_PROGRESS_REPORTER)
        assertTrue(compared.delegatedSuccess())
        assertEquals(refs, compareInput.captured.refs)
        assertEquals(HttpComparisonPart.REQUEST_HEADERS, compareInput.captured.part)
    }

    @Test
    fun `delegated cancellation is preserved`() {
        every { api.project().id() } returns "p"
        every { store.list() } returns listOf(preset("http", WorkflowPresetDefinition(httpSearch = SavedHttpSearch())))
        coEvery { http.search(any(), any()) } throws CancellationException("cancel")
        assertThrows(CancellationException::class.java) {
            runBlocking { service.execute(ExecuteWorkflowPreset("p", "http"), NO_TOOL_PROGRESS_REPORTER) }
        }
    }

    private fun saveInput(projectId: String) = SaveWorkflowPreset(
        projectId, "one", definition = WorkflowPresetDefinition(httpSearch = SavedHttpSearch())
    )

    private fun preset(name: String, definition: WorkflowPresetDefinition) = WorkflowPreset(name, null, definition)
    private fun ref(id: String) = HttpMessageReference(HttpMessageSource.PROXY, id)

    private fun httpResult(status: HttpMessageSearchStatus) = SearchHttpMessagesResult(
        status, "p", emptyList(), 0, 0, 0, 0, false, false, null,
        if (status == HttpMessageSearchStatus.OK) null else "delegated status",
    )

    private fun comparisonResult() = CompareHttpMessagesResult(
        HttpComparisonStatus.OK, "p", HttpComparisonPart.REQUEST_HEADERS, listOf(ref("1"), ref("2")),
        emptyList(), true, 0, error = null,
    )
}
