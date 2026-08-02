package net.portswigger.mcp.presets

import burp.api.montoya.persistence.PersistedObject
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import kotlinx.coroutines.CancellationException
import net.portswigger.mcp.tools.HttpComparisonPart
import net.portswigger.mcp.tools.HttpMessageSource
import net.portswigger.mcp.tools.WebSocketSearchDirection
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class WorkflowPresetStoreTest {
    @Test
    fun `three definitions round trip and survive store reconstruction`() {
        val (storage, values) = storage()
        val store = WorkflowPresetStore(storage)
        store.save(preset("HTTP", WorkflowPresetDefinition(httpSearch = SavedHttpSearch(
            sources = listOf(HttpMessageSource.PROXY), host = "example.test", defaultLimit = 10,
        ))), false)
        store.save(preset("WS", WorkflowPresetDefinition(webSocketSearch = SavedWebSocketSearch(
            direction = WebSocketSearchDirection.SERVER_TO_CLIENT, listenerPort = 8080,
        ))), false)
        store.save(preset("Compare", WorkflowPresetDefinition(httpComparison = SavedHttpComparison(
            part = HttpComparisonPart.RESPONSE_HEADERS, ignoreHeaders = listOf("date"),
        ))), false)

        val reconstructed = WorkflowPresetStore(storage).list()
        assertEquals(listOf("Compare", "HTTP", "WS"), reconstructed.map { it.name })
        assertTrue(reconstructed.single { it.name == "HTTP" }.definition.httpSearch != null)
        assertTrue(reconstructed.single { it.name == "WS" }.definition.webSocketSearch != null)
        assertTrue(reconstructed.single { it.name == "Compare" }.definition.httpComparison != null)
        assertTrue(values.getValue(WORKFLOW_PRESET_STORAGE_KEY).contains("\"version\":1"))
    }

    @Test
    fun `create overwrite delete and case insensitive uniqueness are deterministic`() {
        val (storage, _) = storage()
        val store = WorkflowPresetStore(storage)
        store.save(preset("zeta"), false)
        store.save(preset("Alpha"), false)
        assertThrows(WorkflowPresetAlreadyExistsException::class.java) { store.save(preset(" alpha ".trim()), false) }
        assertEquals(Pair(false, true), store.save(preset("ALPHA", description = "replacement"), true))
        assertEquals(listOf("ALPHA", "zeta"), store.list().map { it.name })
        assertFalse(store.delete("absent"))
        assertTrue(store.delete("alpha"))
        assertEquals(listOf("zeta"), store.list().map { it.name })
    }

    @Test
    fun `one canonical Unicode name key governs save read and delete`() {
        val (storage, _) = storage()
        val store = WorkflowPresetStore(storage)
        store.save(preset("İ"), false)
        assertThrows(WorkflowPresetAlreadyExistsException::class.java) {
            store.save(preset("i\u0307"), false)
        }
        assertEquals(listOf("İ"), WorkflowPresetStore(storage).list().map { it.name })
        assertTrue(store.delete("i\u0307"))
        assertTrue(store.list().isEmpty())
    }

    @Test
    fun `capacity concurrent saves and forbidden sentinel absence are enforced`() {
        val (storage, values) = storage()
        val store = WorkflowPresetStore(storage)
        val executor = Executors.newFixedThreadPool(8)
        repeat(MAX_WORKFLOW_PRESETS) { index ->
            executor.submit { store.save(preset("preset-${index.toString().padStart(2, '0')}"), false) }
        }
        executor.shutdown()
        assertTrue(executor.awaitTermination(10, TimeUnit.SECONDS))
        assertEquals(MAX_WORKFLOW_PRESETS, store.list().size)
        val error = assertThrows(WorkflowPresetStoreException::class.java) {
            store.save(preset("overflow"), false)
        }
        assertEquals(WorkflowPresetStoreFailure.CAPACITY, error.failure)

        val persisted = values.getValue(WORKFLOW_PRESET_STORAGE_KEY)
        listOf("secret-credential-sentinel", "projectId", "cursor", "refs", "webSocketId", "caseSensitive", "searchIn").forEach {
            assertFalse(persisted.contains(it))
        }
        assertTrue(persisted.toByteArray(Charsets.UTF_8).size <= MAX_WORKFLOW_PRESET_ENVELOPE_BYTES)
    }

    @Test
    fun `write side envelope capacity preserves the prior raw value without attempting a write`() {
        val (storage, values) = storage()
        val store = WorkflowPresetStore(storage)
        val largeDefinition = WorkflowPresetDefinition(httpSearch = SavedHttpSearch(
            pathContains = "😀".repeat(1024),
            methods = List(32) { "M".repeat(32) },
            mimeTypes = List(32) { "A".repeat(64) },
        ))
        var successfulWrites = 0
        while (true) {
            val before = values[WORKFLOW_PRESET_STORAGE_KEY]
            val failure = runCatching {
                store.save(
                    preset(
                        "large-${successfulWrites.toString().padStart(2, '0')}",
                        largeDefinition,
                        "😀".repeat(128),
                    ),
                    false,
                )
            }.exceptionOrNull()
            if (failure == null) {
                successfulWrites++
                continue
            }
            assertTrue(failure is WorkflowPresetStoreException)
            assertEquals(WorkflowPresetStoreFailure.CAPACITY, (failure as WorkflowPresetStoreException).failure)
            assertEquals(before, values[WORKFLOW_PRESET_STORAGE_KEY])
            break
        }
        assertTrue(successfulWrites in 1 until MAX_WORKFLOW_PRESETS)
        assertTrue(values.getValue(WORKFLOW_PRESET_STORAGE_KEY).toByteArray(Charsets.UTF_8).size <= MAX_WORKFLOW_PRESET_ENVELOPE_BYTES)
        verify(exactly = successfulWrites) { storage.setString(WORKFLOW_PRESET_STORAGE_KEY, any()) }
    }

    @Test
    fun `caller authored safe strings round trip verbatim without prohibited dedicated fields`() {
        val (storage, values) = storage()
        val store = WorkflowPresetStore(storage)
        val authored = preset(
            name = "caller-authored-name",
            description = "caller-authored-description",
            definition = WorkflowPresetDefinition(httpSearch = SavedHttpSearch(
                host = "caller-authored.example",
                pathContains = "/caller-authored/path",
            )),
        )
        store.save(authored, false)
        assertEquals(authored, WorkflowPresetStore(storage).list().single())
        val raw = values.getValue(WORKFLOW_PRESET_STORAGE_KEY)
        listOf(authored.name, authored.description, authored.definition.httpSearch?.host,
            authored.definition.httpSearch?.pathContains).filterNotNull().forEach { assertTrue(raw.contains(it)) }
        listOf("projectId", "cursor", "refs", "webSocketId", "regex", "caseSensitive", "searchIn",
            "credential", "token", "requestBody", "responseBody").forEach {
            assertFalse(raw.contains("\"$it\":"), "encoded envelope must not contain a dedicated $it field")
        }
    }

    @Test
    fun `path control characters are rejected before storage access or write`() {
        val (storage, _) = storage()
        val store = WorkflowPresetStore(storage)
        assertThrows(IllegalArgumentException::class.java) {
            store.save(preset("invalid", WorkflowPresetDefinition(httpSearch = SavedHttpSearch(
                pathContains = "/safe\nunsafe",
            ))), false)
        }
        verify(exactly = 0) { storage.getString(any()) }
        verify(exactly = 0) { storage.setString(any(), any()) }
    }

    @Test
    fun `write boundary wraps cancellation but does not normalize fatal errors`() {
        val cancellationStorage = mockk<PersistedObject>()
        every { cancellationStorage.getString(any()) } returns null
        every { cancellationStorage.setString(any(), any()) } throws CancellationException("cancelled")
        val cancellation = assertThrows(WorkflowPresetStoreException::class.java) {
            WorkflowPresetStore(cancellationStorage).save(preset("one"), false)
        }
        assertTrue(cancellation.writeAttempted)
        assertTrue(cancellation.cause is CancellationException)

        val fatalStorage = mockk<PersistedObject>()
        every { fatalStorage.getString(any()) } returns null
        every { fatalStorage.setString(any(), any()) } throws AssertionError("fatal")
        assertThrows(AssertionError::class.java) {
            WorkflowPresetStore(fatalStorage).save(preset("one"), false)
        }
    }

    @Test
    fun `post-write mismatch and reread cancellation are uncertain`() {
        val mismatchStorage = mockk<PersistedObject>()
        var mismatchRead = false
        every { mismatchStorage.getString(WORKFLOW_PRESET_STORAGE_KEY) } answers {
            if (mismatchRead) "different persisted value" else null
        }
        every { mismatchStorage.setString(WORKFLOW_PRESET_STORAGE_KEY, any()) } answers {
            mismatchRead = true
        }
        val mismatch = assertThrows(WorkflowPresetStoreException::class.java) {
            WorkflowPresetStore(mismatchStorage).save(preset("one"), false)
        }
        assertEquals(WorkflowPresetStoreFailure.STORAGE, mismatch.failure)
        assertTrue(mismatch.writeAttempted)

        val cancellationStorage = mockk<PersistedObject>()
        var writeInvoked = false
        every { cancellationStorage.getString(WORKFLOW_PRESET_STORAGE_KEY) } answers {
            if (writeInvoked) throw CancellationException("post-write reread") else null
        }
        every { cancellationStorage.setString(WORKFLOW_PRESET_STORAGE_KEY, any()) } answers {
            writeInvoked = true
        }
        val cancelled = assertThrows(WorkflowPresetStoreException::class.java) {
            WorkflowPresetStore(cancellationStorage).save(preset("one"), false)
        }
        assertEquals(WorkflowPresetStoreFailure.STORAGE, cancelled.failure)
        assertTrue(cancelled.writeAttempted)
        assertTrue(cancelled.cause is CancellationException)

        val (sourceStorage, sourceValues) = storage()
        WorkflowPresetStore(sourceStorage).save(preset("one"), false)
        val priorRaw = sourceValues.getValue(WORKFLOW_PRESET_STORAGE_KEY)
        val droppedDeleteStorage = mockk<PersistedObject>()
        every { droppedDeleteStorage.getString(WORKFLOW_PRESET_STORAGE_KEY) } returns priorRaw
        every { droppedDeleteStorage.setString(WORKFLOW_PRESET_STORAGE_KEY, any()) } returns Unit
        val droppedDelete = assertThrows(WorkflowPresetStoreException::class.java) {
            WorkflowPresetStore(droppedDeleteStorage).delete("one")
        }
        assertEquals(WorkflowPresetStoreFailure.STORAGE, droppedDelete.failure)
        assertTrue(droppedDelete.writeAttempted)
        verify(exactly = 1) { droppedDeleteStorage.setString(WORKFLOW_PRESET_STORAGE_KEY, any()) }
    }

    @Test
    fun `malformed unknown and oversized raw storage is preserved`() {
        listOf(
            "{malformed",
            "{\"version\":99,\"presets\":[]}",
            "x".repeat(MAX_WORKFLOW_PRESET_ENVELOPE_BYTES + 1),
        ).forEach { raw ->
            val (storage, values) = storage(mutableMapOf(WORKFLOW_PRESET_STORAGE_KEY to raw))
            val store = WorkflowPresetStore(storage)
            assertThrows(WorkflowPresetStoreException::class.java) { store.list() }
            assertThrows(WorkflowPresetStoreException::class.java) { store.save(preset("new"), false) }
            assertThrows(WorkflowPresetStoreException::class.java) { store.delete("anything") }
            assertEquals(raw, values[WORKFLOW_PRESET_STORAGE_KEY])
            verify(exactly = 0) { storage.setString(WORKFLOW_PRESET_STORAGE_KEY, any()) }
        }
    }

    private fun preset(
        name: String,
        definition: WorkflowPresetDefinition = WorkflowPresetDefinition(httpSearch = SavedHttpSearch()),
        description: String? = null,
    ) = WorkflowPreset(name, description, definition)

    private fun storage(
        values: MutableMap<String, String> = mutableMapOf(),
    ): Pair<PersistedObject, MutableMap<String, String>> {
        val storage = mockk<PersistedObject>()
        every { storage.getString(any()) } answers { values[firstArg()] }
        every { storage.setString(any(), any()) } answers {
            values[firstArg()] = secondArg()
        }
        return storage to values
    }
}
