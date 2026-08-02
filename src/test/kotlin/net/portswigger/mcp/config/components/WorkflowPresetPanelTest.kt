package net.portswigger.mcp.config.components

import net.portswigger.mcp.presets.LocalWorkflowPresetListResult
import net.portswigger.mcp.presets.LocalWorkflowPresetMutationResult
import net.portswigger.mcp.presets.LocalWorkflowPresetStatus
import net.portswigger.mcp.presets.SavedHttpSearch
import net.portswigger.mcp.presets.WorkflowPreset
import net.portswigger.mcp.presets.WorkflowPresetDefinition
import net.portswigger.mcp.presets.WorkflowPresetManagement
import net.portswigger.mcp.presets.workflowPresetNameKey
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.awt.Component
import java.awt.Container
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import javax.swing.JButton
import javax.swing.JPanel
import javax.accessibility.AccessibleRelation
import javax.swing.JTable
import javax.swing.JTextArea
import javax.swing.SwingUtilities

class WorkflowPresetPanelTest {
    @Test
    fun `local panel refreshes creates edits and deletes without an execution surface`() {
        val management = InMemoryManagement(mutableListOf(preset("Existing", "before")))
        val editor = WorkflowPresetEditor { _, existing ->
            if (existing == null) preset("New", "created") else existing.copy(description = "after")
        }
        lateinit var panel: WorkflowPresetPanel
        SwingUtilities.invokeAndWait {
            panel = WorkflowPresetPanel(
                management = management,
                parentComponent = JPanel(),
                editor = editor,
                deleteConfirmation = WorkflowPresetDeleteConfirmation { _, _ -> true },
            )
        }

        try {
            val refresh = panel.named<JButton>("refreshWorkflowPresetsButton")
            val create = panel.named<JButton>("newWorkflowPresetButton")
            val edit = panel.named<JButton>("editWorkflowPresetButton")
            val delete = panel.named<JButton>("deleteWorkflowPresetButton")
            val table = panel.named<JTable>("workflowPresetTable")

            SwingUtilities.invokeAndWait { refresh.doClick() }
            await { table.rowCount == 1 && create.isEnabled }
            SwingUtilities.invokeAndWait { create.doClick() }
            await { table.rowCount == 2 && create.isEnabled }

            SwingUtilities.invokeAndWait {
                table.setRowSelectionInterval(0, 0)
                edit.doClick()
            }
            await { management.snapshot().single { it.name == "Existing" }.description == "after" && edit.isEnabled }

            SwingUtilities.invokeAndWait {
                val row = management.snapshot().indexOfFirst { it.name == "New" }
                table.setRowSelectionInterval(row, row)
                delete.doClick()
            }
            await { management.snapshot().none { it.name == "New" } && !delete.isEnabled }

            assertEquals(listOf("Existing"), management.snapshot().map { it.name })
            assertTrue(management.workerThreads.isNotEmpty())
            assertFalse(management.workerThreads.any { it.contains("AWT-EventQueue") })
            assertTrue(panel.descendants().filterIsInstance<JButton>().none { it.text.contains("Execute", true) })
        } finally {
            panel.cancelBackgroundWorkAndAwait()
        }
    }

    @Test
    fun `cleanup interrupts blocked work suppresses late publication and is idempotent`() {
        val started = CountDownLatch(1)
        val interrupted = AtomicBoolean(false)
        val listCalls = AtomicInteger()
        val management = object : WorkflowPresetManagement {
            override fun list(): LocalWorkflowPresetListResult {
                listCalls.incrementAndGet()
                started.countDown()
                try {
                    CountDownLatch(1).await()
                } catch (_: InterruptedException) {
                    interrupted.set(true)
                }
                return LocalWorkflowPresetListResult(
                    LocalWorkflowPresetStatus.OK,
                    listOf(preset("Late", "must not be published")),
                )
            }

            override fun save(preset: WorkflowPreset, overwrite: Boolean) =
                error("save must not run")

            override fun delete(name: String) = error("delete must not run")
        }
        lateinit var panel: WorkflowPresetPanel
        SwingUtilities.invokeAndWait {
            panel = WorkflowPresetPanel(management, JPanel())
            panel.named<JButton>("refreshWorkflowPresetsButton").doClick()
        }
        assertTrue(started.await(2, TimeUnit.SECONDS))
        val statusBeforeCleanup = panel.named<JTextArea>("workflowPresetStatusText").text

        panel.cancelBackgroundWorkAndAwait()
        panel.cancelBackgroundWorkAndAwait()
        SwingUtilities.invokeAndWait { }

        assertTrue(interrupted.get())
        assertEquals(1, listCalls.get())
        assertEquals(0, panel.named<JTable>("workflowPresetTable").rowCount)
        assertEquals(statusBeforeCleanup, panel.named<JTextArea>("workflowPresetStatusText").text)
        val workerField = WorkflowPresetPanel::class.java.getDeclaredField("worker").apply { isAccessible = true }
        assertTrue((workerField.get(panel) as ThreadPoolExecutor).isTerminated)
        SwingUtilities.invokeAndWait {
            panel.named<JButton>("refreshWorkflowPresetsButton").doClick()
        }
        assertEquals(1, listCalls.get())
    }

    @Test
    fun `duplicate create action is serialized while one possible write is active`() {
        val saveStarted = CountDownLatch(1)
        val releaseSave = CountDownLatch(1)
        val saveCalls = AtomicInteger()
        val stored = CopyOnWriteArrayList<WorkflowPreset>()
        val management = object : WorkflowPresetManagement {
            override fun list() = LocalWorkflowPresetListResult(LocalWorkflowPresetStatus.OK, stored.toList())

            override fun save(preset: WorkflowPreset, overwrite: Boolean): LocalWorkflowPresetMutationResult {
                saveCalls.incrementAndGet()
                saveStarted.countDown()
                releaseSave.await(2, TimeUnit.SECONDS)
                stored += preset
                return LocalWorkflowPresetMutationResult(
                    LocalWorkflowPresetStatus.OK,
                    preset = preset,
                    created = true,
                )
            }

            override fun delete(name: String) = error("delete must not run")
        }
        lateinit var panel: WorkflowPresetPanel
        SwingUtilities.invokeAndWait {
            panel = WorkflowPresetPanel(
                management,
                JPanel(),
                editor = WorkflowPresetEditor { _, _ -> preset("Serialized", "one write") },
            )
        }
        try {
            val create = panel.named<JButton>("newWorkflowPresetButton")
            SwingUtilities.invokeAndWait { create.doClick() }
            assertTrue(saveStarted.await(2, TimeUnit.SECONDS))
            SwingUtilities.invokeAndWait {
                assertFalse(create.isEnabled)
                create.doClick()
            }
            assertEquals(1, saveCalls.get())

            releaseSave.countDown()
            await { create.isEnabled && panel.named<JTable>("workflowPresetTable").rowCount == 1 }
            assertEquals(1, saveCalls.get())
        } finally {
            releaseSave.countDown()
            panel.cancelBackgroundWorkAndAwait()
        }
    }

    @Test
    fun `invalid storage and uncertain mutation are rendered without refresh or automatic retry`() {
        val listCalls = AtomicInteger()
        val saveCalls = AtomicInteger()
        val management = object : WorkflowPresetManagement {
            override fun list(): LocalWorkflowPresetListResult {
                listCalls.incrementAndGet()
                return LocalWorkflowPresetListResult(LocalWorkflowPresetStatus.STORED_DATA_INVALID)
            }

            override fun save(preset: WorkflowPreset, overwrite: Boolean): LocalWorkflowPresetMutationResult {
                saveCalls.incrementAndGet()
                return LocalWorkflowPresetMutationResult(LocalWorkflowPresetStatus.UNCERTAIN)
            }

            override fun delete(name: String) = error("delete must not run")
        }
        lateinit var panel: WorkflowPresetPanel
        SwingUtilities.invokeAndWait {
            panel = WorkflowPresetPanel(
                management,
                JPanel(),
                editor = WorkflowPresetEditor { _, _ -> preset("Uncertain", "reconcile") },
            )
        }
        try {
            val status = panel.named<JTextArea>("workflowPresetStatusText")
            val refresh = panel.named<JButton>("refreshWorkflowPresetsButton")
            val create = panel.named<JButton>("newWorkflowPresetButton")
            SwingUtilities.invokeAndWait { refresh.doClick() }
            await { status.text.contains("original value was preserved") && create.isEnabled }
            assertEquals(1, listCalls.get())

            SwingUtilities.invokeAndWait { create.doClick() }
            await { status.text.contains("Do not retry automatically") && create.isEnabled }
            assertEquals(1, saveCalls.get())
            assertEquals(1, listCalls.get())
            assertEquals(0, panel.named<JTable>("workflowPresetTable").rowCount)
        } finally {
            panel.cancelBackgroundWorkAndAwait()
        }
    }

    @Test
    fun `manager controls expose keyboard focus and accessibility relations without execute actions`() {
        lateinit var panel: WorkflowPresetPanel
        SwingUtilities.invokeAndWait {
            panel = WorkflowPresetPanel(InMemoryManagement(mutableListOf()), JPanel())
        }
        try {
            val buttons = listOf(
                panel.named<JButton>("refreshWorkflowPresetsButton"),
                panel.named<JButton>("newWorkflowPresetButton"),
                panel.named<JButton>("editWorkflowPresetButton"),
                panel.named<JButton>("deleteWorkflowPresetButton"),
            )
            val table = panel.named<JTable>("workflowPresetTable")
            val status = panel.named<JTextArea>("workflowPresetStatusText")
            val selection = panel.named<JTextArea>("workflowPresetSelectionText")

            buttons.forEach { button ->
                assertTrue(button.isFocusable)
                assertTrue(button.accessibleContext.accessibleName.isNotBlank())
                assertTrue(button.accessibleContext.accessibleDescription.isNotBlank())
                assertNotNull(
                    button.accessibleContext.accessibleRelationSet.get(AccessibleRelation.CONTROLLER_FOR),
                )
            }
            assertEquals("Saved workflow presets", table.accessibleContext.accessibleName)
            assertTrue(table.accessibleContext.accessibleDescription.contains("does not execute"))
            assertNotNull(table.accessibleContext.accessibleRelationSet.get(AccessibleRelation.CONTROLLER_FOR))
            assertNotNull(status.accessibleContext.accessibleRelationSet.get(AccessibleRelation.CONTROLLED_BY))
            assertNotNull(selection.accessibleContext.accessibleRelationSet.get(AccessibleRelation.CONTROLLED_BY))
            assertTrue(panel.getFocusTraversalKeys(java.awt.KeyboardFocusManager.FORWARD_TRAVERSAL_KEYS).isNotEmpty())
            assertTrue(buttons.none { it.text.contains("Execute", ignoreCase = true) })
        } finally {
            panel.cancelBackgroundWorkAndAwait()
        }
    }

    private class InMemoryManagement(initial: MutableList<WorkflowPreset>) : WorkflowPresetManagement {
        private val presets = initial
        val workerThreads = CopyOnWriteArrayList<String>()

        @Synchronized
        override fun list(): LocalWorkflowPresetListResult {
            workerThreads += Thread.currentThread().name
            return LocalWorkflowPresetListResult(LocalWorkflowPresetStatus.OK, presets.sortedBy { workflowPresetNameKey(it.name) })
        }

        @Synchronized
        override fun save(preset: WorkflowPreset, overwrite: Boolean): LocalWorkflowPresetMutationResult {
            workerThreads += Thread.currentThread().name
            val index = presets.indexOfFirst { workflowPresetNameKey(it.name) == workflowPresetNameKey(preset.name) }
            if (index >= 0 && !overwrite) {
                return LocalWorkflowPresetMutationResult(LocalWorkflowPresetStatus.ALREADY_EXISTS)
            }
            if (index >= 0) presets[index] = preset else presets += preset
            return LocalWorkflowPresetMutationResult(
                LocalWorkflowPresetStatus.OK,
                preset = preset,
                created = index < 0,
                replaced = index >= 0,
            )
        }

        @Synchronized
        override fun delete(name: String): LocalWorkflowPresetMutationResult {
            workerThreads += Thread.currentThread().name
            val deleted = presets.removeIf { workflowPresetNameKey(it.name) == workflowPresetNameKey(name) }
            return LocalWorkflowPresetMutationResult(LocalWorkflowPresetStatus.OK, deleted = deleted)
        }

        @Synchronized
        fun snapshot(): List<WorkflowPreset> = presets.toList().sortedBy { workflowPresetNameKey(it.name) }
    }

    private fun preset(name: String, description: String) = WorkflowPreset(
        name,
        description,
        WorkflowPresetDefinition(httpSearch = SavedHttpSearch()),
    )

    private fun await(condition: () -> Boolean) {
        val deadline = System.nanoTime() + 3_000_000_000L
        while (System.nanoTime() < deadline) {
            SwingUtilities.invokeAndWait { }
            if (condition()) return
            Thread.sleep(10)
        }
        assertTrue(condition(), "condition did not become true before timeout")
    }

    private inline fun <reified T : Component> Container.named(name: String): T =
        descendants().filterIsInstance<T>().single { it.name == name }

    private fun Container.descendants(): Sequence<Component> = sequence {
        components.forEach { component ->
            yield(component)
            if (component is Container) yieldAll(component.descendants())
        }
    }
}
