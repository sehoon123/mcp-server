package net.portswigger.mcp.presets

import burp.api.montoya.persistence.PersistedObject
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import kotlinx.coroutines.CancellationException
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.util.concurrent.atomic.AtomicInteger

class LocalWorkflowPresetManagerTest {
    @Test
    fun `native manager and MCP adapter store share one project-local envelope`() {
        val (storage, _) = storage()
        val sharedStore = WorkflowPresetStore(storage)
        val manager = LocalWorkflowPresetManager(sharedStore) { "project-a" }

        val created = manager.save(preset("Native"), overwrite = false)
        assertEquals(LocalWorkflowPresetStatus.OK, created.status)
        assertTrue(created.created)
        assertEquals(listOf("Native"), sharedStore.list().map { it.name })

        sharedStore.save(preset("MCP"), overwrite = false)
        val listed = manager.list()
        assertEquals(LocalWorkflowPresetStatus.OK, listed.status)
        assertEquals(listOf("MCP", "Native"), listed.presets.map { it.name })
    }

    @Test
    fun `project transition discards reads and makes a completed write uncertain`() {
        val (storage, _) = storage()
        val store = WorkflowPresetStore(storage)
        store.save(preset("Existing"), overwrite = false)
        val listReads = AtomicInteger()
        val listManager = LocalWorkflowPresetManager(store) {
            if (listReads.getAndIncrement() == 0) "project-a" else "project-b"
        }
        val listed = listManager.list()
        assertEquals(LocalWorkflowPresetStatus.PROJECT_CHANGED, listed.status)
        assertTrue(listed.presets.isEmpty())

        val saveReads = AtomicInteger()
        val saveManager = LocalWorkflowPresetManager(store) {
            if (saveReads.getAndIncrement() == 0) "project-a" else "project-b"
        }
        val saved = saveManager.save(preset("Written"), overwrite = false)
        assertEquals(LocalWorkflowPresetStatus.UNCERTAIN, saved.status)
        assertTrue(store.list().any { it.name == "Written" })
    }

    @Test
    fun `invalid raw data is preserved and never overwritten by the local manager`() {
        val raw = "{invalid"
        val (storage, values) = storage(mutableMapOf(WORKFLOW_PRESET_STORAGE_KEY to raw))
        val manager = LocalWorkflowPresetManager(WorkflowPresetStore(storage)) { "project-a" }

        assertEquals(LocalWorkflowPresetStatus.STORED_DATA_INVALID, manager.list().status)
        assertEquals(LocalWorkflowPresetStatus.STORED_DATA_INVALID, manager.save(preset("New"), false).status)
        assertEquals(LocalWorkflowPresetStatus.STORED_DATA_INVALID, manager.delete("Existing").status)
        assertEquals(raw, values[WORKFLOW_PRESET_STORAGE_KEY])
        verify(exactly = 0) { storage.setString(any(), any()) }
    }

    @Test
    fun `post invocation storage cancellation is uncertain while invalid input is preflighted`() {
        val storage = mockk<PersistedObject>()
        every { storage.getString(any()) } returns null
        every { storage.setString(any(), any()) } throws CancellationException("after invocation")
        val manager = LocalWorkflowPresetManager(WorkflowPresetStore(storage)) { "project-a" }

        assertEquals(LocalWorkflowPresetStatus.UNCERTAIN, manager.save(preset("New"), false).status)
        val invalid = manager.save(preset("bad\nname"), false)
        assertEquals(LocalWorkflowPresetStatus.INVALID_ARGUMENT, invalid.status)
        verify(exactly = 1) { storage.getString(any()) }
        verify(exactly = 1) { storage.setString(any(), any()) }
    }

    @Test
    fun `delete is idempotent and never exposes the project identifier`() {
        val (storage, _) = storage()
        val manager = LocalWorkflowPresetManager(WorkflowPresetStore(storage)) { "sensitive-project-value" }

        val absent = manager.delete("Absent")
        assertEquals(LocalWorkflowPresetStatus.OK, absent.status)
        assertFalse(absent.deleted)
        assertFalse(absent.toString().contains("sensitive-project-value"))
    }

    private fun preset(name: String) = WorkflowPreset(
        name = name,
        definition = WorkflowPresetDefinition(httpSearch = SavedHttpSearch()),
    )

    private fun storage(
        values: MutableMap<String, String> = mutableMapOf(),
    ): Pair<PersistedObject, MutableMap<String, String>> {
        val storage = mockk<PersistedObject>()
        every { storage.getString(any()) } answers { values[firstArg()] }
        every { storage.setString(any(), any()) } answers { values[firstArg()] = secondArg() }
        return storage to values
    }
}
