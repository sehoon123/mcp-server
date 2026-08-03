package net.portswigger.mcp.config.components

import net.portswigger.mcp.presets.SavedHttpComparison
import net.portswigger.mcp.presets.SavedHttpSearch
import net.portswigger.mcp.presets.SavedWebSocketSearch
import net.portswigger.mcp.presets.WorkflowPreset
import net.portswigger.mcp.presets.WorkflowPresetDefinition
import net.portswigger.mcp.presets.WorkflowPresetType
import net.portswigger.mcp.tools.HttpComparisonEncoding
import net.portswigger.mcp.tools.HttpComparisonPart
import net.portswigger.mcp.tools.HttpMessageSource
import net.portswigger.mcp.tools.WebSocketSearchDirection
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.awt.Component
import java.awt.Container
import java.awt.event.ActionEvent
import java.awt.event.KeyEvent
import javax.accessibility.AccessibleRelation
import javax.swing.JButton
import javax.swing.JComboBox
import javax.swing.JComponent
import javax.swing.JLabel
import javax.swing.JRootPane
import javax.swing.JTextArea
import javax.swing.JTextField
import javax.swing.KeyStroke
import javax.swing.SwingUtilities

class WorkflowPresetEditorTest {
    @Test
    fun `structured comparison editor round trips every saved setting and locks identity`() {
        val existing = WorkflowPreset(
            name = "Compare APIs",
            description = "Stable response comparison",
            definition = WorkflowPresetDefinition(httpComparison = SavedHttpComparison(
                part = HttpComparisonPart.RESPONSE_HEADERS,
                limitBytesPerMessage = 65_536,
                excerptEncoding = HttpComparisonEncoding.BASE64,
                ignoreHeaders = listOf("date", "etag"),
                includeResponseVariations = false,
            )),
        )
        lateinit var form: WorkflowPresetEditorForm
        var result: WorkflowPreset? = null
        SwingUtilities.invokeAndWait {
            form = WorkflowPresetEditorForm(existing)
            assertFalse(form.named<JTextField>("workflowPresetNameField").isEditable)
            result = form.toPreset()
        }
        assertEquals(existing, result)
    }

    @Test
    fun `HTTP form canonicalizes bounded list fields without runtime-only inputs`() {
        lateinit var form: WorkflowPresetEditorForm
        var result: WorkflowPreset? = null
        SwingUtilities.invokeAndWait {
            form = WorkflowPresetEditorForm(null)
            form.named<JTextField>("workflowPresetNameField").text = "API inventory"
            form.named<JTextField>("workflowPresetHttpSourcesField").text = "proxy, site_map"
            form.named<JTextField>("workflowPresetHttpHostField").text = "api.example.test"
            form.named<JTextField>("workflowPresetHttpPathField").text = "/v1/"
            form.named<JTextField>("workflowPresetHttpMethodsField").text = "get, post"
            form.named<JTextField>("workflowPresetHttpStatusCodesField").text = "200, 404"
            form.named<JTextField>("workflowPresetHttpMimeTypesField").text = "json, html"
            form.named<JComboBox<*>>("workflowPresetHttpInScopeSelector").selectedIndex = 1
            form.named<JTextField>("workflowPresetHttpDefaultLimitField").text = "25"
            result = form.toPreset()
        }
        assertEquals(
            SavedHttpSearch(
                sources = listOf(HttpMessageSource.PROXY, HttpMessageSource.SITE_MAP),
                host = "api.example.test",
                pathContains = "/v1/",
                methods = listOf("GET", "POST"),
                statusCodes = listOf(200, 404),
                mimeTypes = listOf("JSON", "HTML"),
                inScopeOnly = true,
                defaultLimit = 25,
            ),
            result?.definition?.httpSearch,
        )
    }

    @Test
    fun `WebSocket form creates only safe saved fields and rejects invalid numeric bounds`() {
        lateinit var form: WorkflowPresetEditorForm
        var valid: WorkflowPreset? = null
        SwingUtilities.invokeAndWait {
            form = WorkflowPresetEditorForm(null)
            form.named<JTextField>("workflowPresetNameField").text = "Socket metadata"
            form.named<JTextField>("workflowPresetDescriptionField").text = "Direction and listener filter"
            form.named<JComboBox<*>>("workflowPresetTypeSelector").selectedIndex = WorkflowPresetType.WEBSOCKET_SEARCH.ordinal
            form.named<JComboBox<*>>("workflowPresetWebSocketDirectionSelector").selectedIndex = 1
            form.named<JTextField>("workflowPresetWebSocketListenerPortField").text = "8080"
            form.named<JComboBox<*>>("workflowPresetWebSocketNewestFirstSelector").selectedIndex = 2
            form.named<JTextField>("workflowPresetWebSocketDefaultLimitField").text = "20"
            valid = form.toPreset()
        }
        assertEquals(
            SavedWebSocketSearch(
                direction = WebSocketSearchDirection.CLIENT_TO_SERVER,
                listenerPort = 8080,
                newestFirst = false,
                defaultLimit = 20,
            ),
            valid?.definition?.webSocketSearch,
        )

        SwingUtilities.invokeAndWait {
            form.named<JTextField>("workflowPresetWebSocketListenerPortField").text = "70000"
            assertNull(form.toPreset())
        }
    }

    @Test
    fun `editor validates on change and publishes a privacy-bounded execution-neutral preview`() {
        lateinit var form: WorkflowPresetEditorForm
        val validity = mutableListOf<Boolean>()
        SwingUtilities.invokeAndWait {
            form = WorkflowPresetEditorForm(null)
            form.setValidationListener(validity::add)

            assertFalse(validity.last())
            assertTrue(
                form.named<JTextArea>("workflowPresetInputPreviewText").text
                    .contains("available when the settings are valid"),
            )

            form.named<JTextField>("workflowPresetNameField").text = "Live validation"
            form.named<JTextField>("workflowPresetHttpHostField").text = "private-preview-host.test"
            form.named<JTextField>("workflowPresetHttpDefaultLimitField").text = "25"

            assertTrue(validity.last())
            assertTrue(form.named<JTextArea>("workflowPresetValidationText").text.startsWith("Preset settings are valid."))
            val preview = form.named<JTextArea>("workflowPresetInputPreviewText").text
            assertTrue(preview.contains("host filter set"))
            assertTrue(preview.contains("page limit 25"))
            assertTrue(preview.contains("never reads or executes traffic"))
            assertFalse(preview.contains("private-preview-host.test"))

            form.named<JTextField>("workflowPresetHttpDefaultLimitField").text = "51"
            assertFalse(validity.last())
            assertTrue(form.named<JTextArea>("workflowPresetValidationText").text.startsWith("Preset settings are invalid."))
            assertTrue(
                form.named<JTextArea>("workflowPresetInputPreviewText").text
                    .contains("available when the settings are valid"),
            )
        }
    }

    @Test
    fun `real save control tracks new existing valid and invalid form states`() {
        SwingUtilities.invokeAndWait {
            val newForm = WorkflowPresetEditorForm(null)
            var accepted: WorkflowPreset? = null
            val createButton = createWorkflowPresetSaveButton(
                creating = true,
                form = newForm,
                onAccepted = { accepted = it },
            )
            assertEquals("saveWorkflowPresetEditButton", createButton.name)
            assertEquals("Create preset", createButton.text)
            assertFalse(createButton.isEnabled)

            newForm.named<JTextField>("workflowPresetNameField").text = "Button state"
            assertTrue(createButton.isEnabled)
            newForm.named<JTextField>("workflowPresetHttpDefaultLimitField").text = "51"
            assertFalse(createButton.isEnabled)
            newForm.named<JTextField>("workflowPresetHttpDefaultLimitField").text = "50"
            assertTrue(createButton.isEnabled)
            createButton.doClick()
            assertEquals("Button state", accepted?.name)

            val existing = WorkflowPreset(
                name = "Existing",
                definition = WorkflowPresetDefinition(httpSearch = SavedHttpSearch()),
            )
            val existingForm = WorkflowPresetEditorForm(existing)
            val saveButton = createWorkflowPresetSaveButton(
                creating = false,
                form = existingForm,
                onAccepted = {},
            )
            assertEquals("Save changes", saveButton.text)
            assertTrue(saveButton.isEnabled)
        }
    }

    @Test
    fun `oversized pasted text is rejected before list expansion and hidden fields do not block another type`() {
        SwingUtilities.invokeAndWait {
            val form = WorkflowPresetEditorForm(null)
            val validity = mutableListOf<Boolean>()
            form.setValidationListener(validity::add)
            form.named<JTextField>("workflowPresetNameField").text = "Bounded paste"
            form.named<JTextField>("workflowPresetHttpMethodsField").text =
                List(5_000) { "GET" }.joinToString(",")

            assertFalse(validity.last())
            assertTrue(form.named<JTextArea>("workflowPresetValidationText").text.startsWith("Preset settings are invalid."))
            assertTrue(
                form.named<JTextArea>("workflowPresetInputPreviewText").text
                    .contains("available when the settings are valid"),
            )

            form.named<JComboBox<*>>("workflowPresetTypeSelector").selectedIndex =
                WorkflowPresetType.WEBSOCKET_SEARCH.ordinal
            assertTrue(validity.last())
            assertNotNull(form.toPreset()?.definition?.webSocketSearch)
        }
    }

    @Test
    fun `all editor bounds fail closed and publish only a categorical validation message`() {
        SwingUtilities.invokeAndWait {
            fun invalid(mutator: (WorkflowPresetEditorForm) -> Unit) {
                val form = WorkflowPresetEditorForm(null)
                form.named<JTextField>("workflowPresetNameField").text = "Bounded preset"
                mutator(form)
                assertNull(form.toPreset())
                val validation = form.named<JTextArea>("workflowPresetValidationText")
                assertTrue(validation.text.startsWith("Preset settings are invalid."))
                assertFalse(validation.text.contains("Bounded preset"))
            }

            invalid { it.named<JTextField>("workflowPresetNameField").text = "" }
            invalid { it.named<JTextField>("workflowPresetNameField").text = "n".repeat(65) }
            invalid { it.named<JTextField>("workflowPresetDescriptionField").text = "d".repeat(257) }
            invalid { it.named<JTextField>("workflowPresetHttpSourcesField").text = "proxy, proxy" }
            invalid { it.named<JTextField>("workflowPresetHttpStatusCodesField").text = "99" }
            invalid { it.named<JTextField>("workflowPresetHttpMethodsField").text = (1..33).joinToString(",") { "M$it" } }
            invalid { it.named<JTextField>("workflowPresetHttpDefaultLimitField").text = "51" }
            invalid {
                it.named<JComboBox<*>>("workflowPresetTypeSelector").selectedIndex = WorkflowPresetType.WEBSOCKET_SEARCH.ordinal
                it.named<JTextField>("workflowPresetWebSocketListenerPortField").text = "0"
            }
            invalid {
                it.named<JComboBox<*>>("workflowPresetTypeSelector").selectedIndex = WorkflowPresetType.HTTP_COMPARISON.ordinal
                it.named<JTextField>("workflowPresetComparisonLimitField").text = "1048577"
            }
        }
    }

    @Test
    fun `text-field Enter has no destructive default while Escape remains explicit cancellation`() {
        SwingUtilities.invokeAndWait {
            val rootPane = JRootPane().apply { defaultButton = JButton("unsafe cancel") }
            var cancelled = false

            installWorkflowPresetEditorCancellation(rootPane) { cancelled = true }

            assertNull(rootPane.defaultButton)
            val escape = KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0)
            val actionKey = rootPane.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).get(escape)
            assertEquals("cancel-preset-editor", actionKey)
            rootPane.actionMap.get(actionKey).actionPerformed(
                ActionEvent(rootPane, ActionEvent.ACTION_PERFORMED, "escape"),
            )
            assertTrue(cancelled)
        }
    }

    @Test
    fun `editor controls are keyboard reachable labelled and contain no runtime-only fields`() {
        lateinit var form: WorkflowPresetEditorForm
        SwingUtilities.invokeAndWait {
            form = WorkflowPresetEditorForm(null)
        }

        val names = form.descendants().mapNotNull(Component::getName).map(String::lowercase).toList()
        listOf(
            "projectid",
            "cursor",
            "reference",
            "connectionid",
            "token",
            "credential",
            "traffic",
            "result",
            "contentpredicate",
        ).forEach { forbidden ->
            assertTrue(names.none { forbidden in it }, "editor must not expose a $forbidden control")
        }
        val inputs = form.descendants().filterIsInstance<JComponent>().filter {
            it is JTextField || it is JComboBox<*>
        }.toList()
        assertTrue(inputs.isNotEmpty())
        inputs.forEach { input ->
            assertTrue(input.isFocusable)
            assertTrue(input.name?.isNotBlank() == true)
            assertNotNull(input.accessibleContext.accessibleRelationSet.get(AccessibleRelation.LABELED_BY))
        }
        val labels = form.descendants().filterIsInstance<JLabel>().toList()
        assertTrue(labels.isNotEmpty())
        assertTrue(labels.all { it.labelFor != null })
        assertTrue(
            form.named<JTextArea>("workflowPresetValidationText")
                .accessibleContext.accessibleDescription.isNotBlank(),
        )
        val preview = form.named<JTextArea>("workflowPresetInputPreviewText")
        assertTrue(preview.accessibleContext.accessibleDescription.contains("never reads or executes traffic"))
        assertFalse(preview.text.contains("project", ignoreCase = true))
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
