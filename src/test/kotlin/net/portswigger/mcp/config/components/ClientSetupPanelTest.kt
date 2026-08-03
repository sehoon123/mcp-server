package net.portswigger.mcp.config.components

import io.mockk.every
import io.mockk.mockkObject
import io.mockk.unmockkObject
import io.mockk.verify
import net.portswigger.mcp.config.Dialogs
import net.portswigger.mcp.providers.ClientSetupDefinition
import net.portswigger.mcp.providers.ClientSetupEndpoint
import net.portswigger.mcp.providers.ClientSetupId
import net.portswigger.mcp.providers.ConnectionDoctor
import net.portswigger.mcp.providers.DoctorExchange
import net.portswigger.mcp.providers.DoctorListenerCode
import net.portswigger.mcp.providers.DoctorRequestConfig
import net.portswigger.mcp.providers.Provider
import net.portswigger.mcp.providers.ProviderInstallConfig
import net.portswigger.mcp.providers.ProviderInstallOperation
import org.junit.jupiter.api.Test
import java.awt.Component
import java.awt.Container
import java.awt.KeyboardFocusManager
import java.awt.event.InputEvent
import java.awt.event.KeyEvent
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import javax.accessibility.AccessibleRelation
import javax.swing.JButton
import javax.swing.JComboBox
import javax.swing.JPanel
import javax.swing.JTextArea
import javax.swing.KeyStroke
import javax.swing.SwingUtilities
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class ClientSetupPanelTest {
    @Test
    fun `selector exposes exactly five safe previews and only Claude has an installer`() {
        val copied = AtomicReference<String>()
        val endpointSnapshots = AtomicInteger()
        val installSnapshots = AtomicInteger()
        lateinit var panel: ClientSetupPanel
        SwingUtilities.invokeAndWait {
            panel = createPanel(
                clipboard = ClientSetupClipboard(copied::set),
                endpointProvider = {
                    endpointSnapshots.incrementAndGet()
                    ClientSetupEndpoint.from("::1", 9999)
                },
                installConfigProvider = {
                    installSnapshots.incrementAndGet()
                    installConfig()
                },
            )
            val selector = panel.findNamed<JComboBox<*>>("clientSetupSelector")
            assertEquals(5, selector.itemCount)
            assertEquals(
                listOf(
                    "Claude Desktop",
                    "Claude Code",
                    "VS Code / GitHub Copilot",
                    "Cursor",
                    "OpenAI Codex",
                ),
                (0 until selector.itemCount).map { selector.getItemAt(it).toString() },
            )
            assertNotNull(panel.findNamedOrNull<JButton>("installClaudeDesktopButton"))

            for (index in 0 until selector.itemCount) {
                selector.selectedIndex = index
                val preview = panel.findNamed<JTextArea>("clientSetupPreview")
                assertTrue(preview.text.contains("http://127.0.0.1:9876/mcp"))
                assertFalse(preview.text.contains(SENTINEL_TOKEN))
                assertFalse(preview.text.contains("/Users/private"))
                val selectedId = (selector.getItemAt(index) as ClientSetupDefinition).id
                assertEquals(
                    selectedId == ClientSetupId.CLAUDE_DESKTOP,
                    panel.findNamedOrNull<JButton>("installClaudeDesktopButton") != null,
                )
                panel.findNamed<JButton>("copySetupPreviewButton").doClick()
                assertEquals(preview.text, copied.get())
            }

            assertEquals(0, endpointSnapshots.get())
            assertEquals(0, installSnapshots.get())
            panel.findNamed<JButton>("refreshSetupPreviewButton").doClick()
            assertEquals(1, endpointSnapshots.get())
            assertTrue(panel.findNamed<JTextArea>("clientSetupPreview").text.contains("http://[::1]:9999/mcp"))
            panel.cleanup()
        }
    }

    @Test
    fun `Claude install captures one immutable snapshot and serializes duplicate clicks`() {
        mockkObject(Dialogs)
        try {
            val published = CountDownLatch(1)
            every { Dialogs.showMessageDialog(any(), any(), any()) } answers {
                published.countDown()
                Unit
            }
            val started = CountDownLatch(1)
            val release = CountDownLatch(1)
            val completed = CountDownLatch(1)
            val calls = AtomicInteger()
            val installedConfig = AtomicReference<ProviderInstallConfig>()
            val provider = provider { config ->
                calls.incrementAndGet()
                installedConfig.set(config)
                started.countDown()
                release.await(5, TimeUnit.SECONDS)
                completed.countDown()
                "arbitrary provider result must not be published"
            }
            var displayed = installConfig("snapshot-one-token-value-000000000001")
            val notice = WarningLabel().apply { isVisible = true }
            lateinit var panel: ClientSetupPanel
            lateinit var button: JButton
            SwingUtilities.invokeAndWait {
                panel = createPanel(
                    provider = provider,
                    notice = notice,
                    installConfigProvider = { displayed },
                )
                button = panel.findNamed("installClaudeDesktopButton")
                button.doClick()
                button.doClick()
            }
            assertTrue(started.await(5, TimeUnit.SECONDS))
            displayed = installConfig("snapshot-two-token-value-000000000002", 9999)
            SwingUtilities.invokeAndWait { assertFalse(button.isEnabled) }
            release.countDown()
            assertTrue(completed.await(5, TimeUnit.SECONDS))
            assertTrue(published.await(5, TimeUnit.SECONDS))

            assertEquals(1, calls.get())
            assertEquals("snapshot-one-token-value-000000000001", installedConfig.get().localBearerToken)
            assertEquals(9876, installedConfig.get().port)
            SwingUtilities.invokeAndWait {
                assertTrue(button.isEnabled)
                assertFalse(notice.isVisible)
                panel.cleanup()
            }
            verify(exactly = 1) {
                Dialogs.showMessageDialog(
                    any(),
                    "Claude Desktop installation completed with an owner-only backup. Restart Claude Desktop before reconnecting.",
                    any(),
                )
            }
        } finally {
            unmockkObject(Dialogs)
        }
    }

    @Test
    fun `cleanup during Claude confirmation prevents credential capture and installation`() {
        mockkObject(Dialogs)
        try {
            val installSnapshots = AtomicInteger()
            val executions = AtomicInteger()
            lateinit var panel: ClientSetupPanel
            every { Dialogs.showConfirmDialog(any(), any(), any()) } answers {
                panel.cancelBackgroundWork()
                javax.swing.JOptionPane.YES_OPTION
            }
            every { Dialogs.showMessageDialog(any(), any(), any()) } returns Unit
            SwingUtilities.invokeAndWait {
                panel = createPanel(
                    provider = provider(confirmation = "Confirm installation") {
                        executions.incrementAndGet()
                        null
                    },
                    installConfigProvider = {
                        installSnapshots.incrementAndGet()
                        installConfig()
                    },
                )
                panel.findNamed<JButton>("installClaudeDesktopButton").doClick()
            }
            assertEquals(0, installSnapshots.get())
            assertEquals(0, executions.get())
            verify(exactly = 0) { Dialogs.showMessageDialog(any(), any(), any()) }
        } finally {
            unmockkObject(Dialogs)
        }
    }

    @Test
    fun `manual extraction never captures the bearer and executes off EDT`() {
        mockkObject(Dialogs)
        try {
            val published = CountDownLatch(1)
            every { Dialogs.showMessageDialog(any(), any(), any()) } answers {
                published.countDown()
                Unit
            }
            val completed = CountDownLatch(1)
            val installSnapshots = AtomicInteger()
            val prepareCalls = AtomicInteger()
            lateinit var panel: ClientSetupPanel
            SwingUtilities.invokeAndWait {
                panel = createPanel(
                    prepareExtraction = {
                        assertTrue(SwingUtilities.isEventDispatchThread())
                        prepareCalls.incrementAndGet()
                        ProviderInstallOperation {
                            assertFalse(SwingUtilities.isEventDispatchThread())
                            completed.countDown()
                            "path-like arbitrary result /Users/private/proxy.jar"
                        }
                    },
                    installConfigProvider = {
                        installSnapshots.incrementAndGet()
                        installConfig()
                    },
                )
                panel.findNamed<JButton>("extractProxyJarButton").doClick()
            }
            assertTrue(completed.await(5, TimeUnit.SECONDS))
            assertTrue(published.await(5, TimeUnit.SECONDS))
            SwingUtilities.invokeAndWait { panel.cleanup() }
            assertEquals(1, prepareCalls.get())
            assertEquals(0, installSnapshots.get())
            verify(exactly = 1) {
                Dialogs.showMessageDialog(any(), "Proxy jar extracted successfully.", any())
            }
        } finally {
            unmockkObject(Dialogs)
        }
    }

    @Test
    fun `Doctor snapshots on EDT runs off EDT and copies only controlled evidence`() {
        val calls = AtomicInteger()
        val snapshots = AtomicInteger()
        val captured = AtomicReference<DoctorRequestConfig>()
        val copied = AtomicReference<String>()
        val completed = CountDownLatch(1)
        val doctor = ConnectionDoctor(DoctorExchange { config ->
            assertFalse(SwingUtilities.isEventDispatchThread())
            calls.incrementAndGet()
            captured.set(config)
            completed.countDown()
            401
        })
        lateinit var panel: ClientSetupPanel
        SwingUtilities.invokeAndWait {
            panel = createPanel(
                doctor = doctor,
                clipboard = ClientSetupClipboard(copied::set),
                doctorConfigProvider = {
                    assertTrue(SwingUtilities.isEventDispatchThread())
                    snapshots.incrementAndGet()
                    DoctorRequestConfig("127.0.0.1", 9876, SENTINEL_TOKEN, DoctorListenerCode.RUNNING)
                },
            )
            val button = panel.findNamed<JButton>("runConnectionDoctorButton")
            button.doClick()
            button.doClick()
        }
        assertTrue(completed.await(5, TimeUnit.SECONDS))
        assertTrue(awaitOnEdt {
            panel.findNamed<WrappingText>("doctorResultText").text.contains("rejected")
        })
        SwingUtilities.invokeAndWait {
            val result = panel.findNamed<WrappingText>("doctorResultText").text
            assertTrue(result.contains("rejected"))
            panel.findNamed<JButton>("copyDoctorEvidenceButton").doClick()
            panel.cleanup()
        }

        assertEquals(1, calls.get())
        assertEquals(1, snapshots.get())
        assertEquals(SENTINEL_TOKEN, captured.get().bearerToken)
        val evidence = copied.get()
        assertNotNull(evidence)
        assertTrue(evidence.contains("CREDENTIAL_REJECTED"))
        assertTrue(evidence.lines().contains("Scope: LOCAL_ADMISSION_ONLY EXTERNAL_CLIENT_NOT_TESTED"))
        listOf(SENTINEL_TOKEN, "Authorization", "127.0.0.1", "9876", "/Users/").forEach { forbidden ->
            assertFalse(evidence.contains(forbidden))
        }
    }

    @Test
    fun `endpoint changes invalidate published Doctor evidence without exposing context`() {
        val copied = AtomicReference<String?>()
        lateinit var panel: ClientSetupPanel
        SwingUtilities.invokeAndWait {
            panel = createPanel(clipboard = ClientSetupClipboard(copied::set))
            panel.markDoctorResultStale(DoctorResultStaleReason.CREDENTIAL_ROTATION_ATTEMPTED)
            assertTrue(panel.findNamed<WrappingText>("doctorResultText").text.contains("has not run"))
            assertFalse(panel.findNamed<JButton>("copyDoctorEvidenceButton").isEnabled)
            panel.findNamed<JButton>("runConnectionDoctorButton").doClick()
        }
        assertTrue(awaitOnEdt {
            panel.findNamed<WrappingText>("doctorResultText").text.contains("admitted")
        })

        SwingUtilities.invokeAndWait {
            val copyEvidence = panel.findNamed<JButton>("copyDoctorEvidenceButton")
            assertTrue(copyEvidence.isEnabled)
            copyEvidence.doClick()
            assertNotNull(copied.get())
            copied.set(null)

            panel.markEndpointStale()

            val staleResult = panel.findNamed<WrappingText>("doctorResultText").text
            assertTrue(staleResult.contains("local-admission check no longer applies"))
            assertTrue(staleResult.contains("displayed endpoint changed"))
            assertTrue(staleResult.contains("does not prove that an external client works"))
            listOf(SENTINEL_TOKEN, "Authorization", "127.0.0.1", "9876", "/Users/", "C:\\").forEach { forbidden ->
                assertFalse(staleResult.contains(forbidden))
            }
            assertFalse(copyEvidence.isEnabled)
            copyEvidence.doClick()
            assertNull(copied.get())
            panel.findNamed<JButton>("runConnectionDoctorButton").doClick()
        }
        assertTrue(awaitOnEdt {
            panel.findNamed<WrappingText>("doctorResultText").text.contains("admitted") &&
                panel.findNamed<JButton>("copyDoctorEvidenceButton").isEnabled
        })
        SwingUtilities.invokeAndWait { panel.cleanup() }
    }

    @Test
    fun `context generation fences an in-flight Doctor completion`() {
        val started = CountDownLatch(1)
        val release = CountDownLatch(1)
        val completed = CountDownLatch(1)
        val copied = AtomicReference<String?>()
        val doctor = ConnectionDoctor(DoctorExchange {
            started.countDown()
            try {
                release.await(5, TimeUnit.SECONDS)
                400
            } finally {
                completed.countDown()
            }
        })
        lateinit var panel: ClientSetupPanel
        SwingUtilities.invokeAndWait {
            panel = createPanel(
                doctor = doctor,
                clipboard = ClientSetupClipboard(copied::set),
            )
            panel.findNamed<JButton>("runConnectionDoctorButton").doClick()
        }
        assertTrue(started.await(5, TimeUnit.SECONDS))

        SwingUtilities.invokeAndWait {
            panel.markDoctorResultStale(DoctorResultStaleReason.LISTENER_STATE_CHANGED)
            val staleResult = panel.findNamed<WrappingText>("doctorResultText").text
            assertTrue(staleResult.contains("local listener state changed"))
            assertTrue(staleResult.contains("Run a new check when available"))
            assertFalse(panel.findNamed<JButton>("copyDoctorEvidenceButton").isEnabled)
        }

        release.countDown()
        assertTrue(completed.await(5, TimeUnit.SECONDS))
        assertTrue(awaitOnEdt { panel.findNamed<JButton>("runConnectionDoctorButton").isEnabled })
        SwingUtilities.invokeAndWait {
            val staleResult = panel.findNamed<WrappingText>("doctorResultText").text
            assertTrue(staleResult.contains("local listener state changed"))
            assertFalse(staleResult.contains("admitted"))
            assertFalse(panel.findNamed<JButton>("copyDoctorEvidenceButton").isEnabled)
            assertTrue(
                panel.findNamed<WrappingText>("clientSetupActionStatus").text.contains("result discarded"),
            )
            assertNull(copied.get())
            panel.cleanup()
        }
    }

    @Test
    fun `cleanup interrupts an in-flight Doctor and suppresses late result publication`() {
        val started = CountDownLatch(1)
        val interrupted = CountDownLatch(1)
        val doctor = ConnectionDoctor(DoctorExchange {
            started.countDown()
            try {
                CountDownLatch(1).await()
                400
            } catch (failure: InterruptedException) {
                interrupted.countDown()
                throw failure
            }
        })
        lateinit var panel: ClientSetupPanel
        lateinit var result: WrappingText
        SwingUtilities.invokeAndWait {
            panel = createPanel(doctor = doctor)
            result = panel.findNamed("doctorResultText")
            panel.findNamed<JButton>("runConnectionDoctorButton").doClick()
        }
        assertTrue(started.await(5, TimeUnit.SECONDS))
        panel.cancelBackgroundWork()
        panel.cleanup()
        assertTrue(interrupted.await(5, TimeUnit.SECONDS))
        SwingUtilities.invokeAndWait {
            assertTrue(result.text.contains("running"))
            assertFalse(panel.findNamed<JButton>("copyDoctorEvidenceButton").isEnabled)
        }
    }

    @Test
    fun `cleanup suppresses late provider completion UI`() {
        mockkObject(Dialogs)
        try {
            every { Dialogs.showMessageDialog(any(), any(), any()) } returns Unit
            val started = CountDownLatch(1)
            val release = CountDownLatch(1)
            val completed = CountDownLatch(1)
            val provider = provider {
                started.countDown()
                try {
                    release.await(5, TimeUnit.SECONDS)
                } finally {
                    completed.countDown()
                }
                "completed after cleanup"
            }
            val notice = WarningLabel().apply { isVisible = true }
            lateinit var panel: ClientSetupPanel
            SwingUtilities.invokeAndWait {
                panel = createPanel(provider = provider, notice = notice)
                panel.findNamed<JButton>("installClaudeDesktopButton").doClick()
            }
            assertTrue(started.await(5, TimeUnit.SECONDS))
            panel.cancelBackgroundWork()
            panel.cancelBackgroundWork()
            panel.cleanup()
            release.countDown()
            assertTrue(completed.await(5, TimeUnit.SECONDS))
            SwingUtilities.invokeAndWait { }
            assertTrue(notice.isVisible)
            verify(exactly = 0) { Dialogs.showMessageDialog(any(), any(), any()) }
        } finally {
            unmockkObject(Dialogs)
        }
    }

    @Test
    fun `setup controls expose accessible labels and descriptions`() {
        lateinit var panel: ClientSetupPanel
        SwingUtilities.invokeAndWait {
            panel = createPanel()
            val selector = panel.findNamed<JComboBox<*>>("clientSetupSelector")
            val preview = panel.findNamed<JTextArea>("clientSetupPreview")
            assertTrue(selector.accessibleContext.accessibleName.isNotBlank())
            assertTrue(selector.accessibleContext.accessibleDescription.isNotBlank())
            assertTrue(preview.accessibleContext.accessibleName.isNotBlank())
            assertTrue(preview.isFocusable)
            assertTrue(
                preview.getFocusTraversalKeys(KeyboardFocusManager.FORWARD_TRAVERSAL_KEYS)
                    .contains(KeyStroke.getKeyStroke(KeyEvent.VK_TAB, 0)),
            )
            assertTrue(
                preview.getFocusTraversalKeys(KeyboardFocusManager.BACKWARD_TRAVERSAL_KEYS)
                    .contains(KeyStroke.getKeyStroke(KeyEvent.VK_TAB, InputEvent.SHIFT_DOWN_MASK)),
            )
            val runDoctor = panel.findNamed<JButton>("runConnectionDoctorButton")
            assertNotNull(
                runDoctor.accessibleContext.accessibleRelationSet
                    .get(AccessibleRelation.CONTROLLER_FOR),
            )
            val copyEvidenceDescription = panel.findNamed<JButton>("copyDoctorEvidenceButton")
                .accessibleContext.accessibleDescription
            assertTrue(copyEvidenceDescription.contains("current endpoint"))
            assertTrue(copyEvidenceDescription.contains("local-admission-only"))
            assertTrue(copyEvidenceDescription.contains("external client"))
            val install = panel.findNamed<JButton>("installClaudeDesktopButton")
            assertNotNull(
                install.accessibleContext.accessibleRelationSet
                    .get(AccessibleRelation.CONTROLLER_FOR),
            )
            assertTrue(panel.findNamed<WrappingText>("clientSetupActionStatus").isVisible)
            panel.descendants().filterIsInstance<JButton>().filter { it.name != null }.forEach { button ->
                assertTrue(button.isFocusPainted)
                assertTrue(button.accessibleContext.accessibleName.isNotBlank())
                assertTrue(button.accessibleContext.accessibleDescription.isNotBlank())
            }
            panel.cleanup()
        }
    }

    private fun createPanel(
        provider: Provider? = provider { null },
        prepareExtraction: (() -> ProviderInstallOperation?)? = { null },
        notice: WarningLabel = WarningLabel().apply { isVisible = true },
        clipboard: ClientSetupClipboard = ClientSetupClipboard { },
        doctor: ConnectionDoctor = ConnectionDoctor(DoctorExchange { 400 }),
        endpointProvider: () -> ClientSetupEndpoint = { ClientSetupEndpoint.from("127.0.0.1", 9876) },
        installConfigProvider: () -> ProviderInstallConfig = { installConfig() },
        doctorConfigProvider: () -> DoctorRequestConfig = {
            DoctorRequestConfig("127.0.0.1", 9876, SENTINEL_TOKEN, DoctorListenerCode.RUNNING)
        },
    ) = ClientSetupPanel(
        initialEndpoint = ClientSetupEndpoint.from("127.0.0.1", 9876),
        claudeDesktopInstaller = provider,
        prepareProxyExtraction = prepareExtraction,
        reinstallNotice = notice,
        parentComponent = JPanel(),
        endpointProvider = endpointProvider,
        installConfigProvider = installConfigProvider,
        doctorConfigProvider = doctorConfigProvider,
        connectionDoctor = doctor,
        clipboard = clipboard,
    )

    private fun provider(
        confirmation: String? = null,
        install: (ProviderInstallConfig) -> String?,
    ): Provider = object : Provider {
        override val name = "Claude Desktop"
        override val installButtonText = "Install to Claude Desktop"
        override val confirmationText: String? = confirmation

        override fun prepareInstall(config: ProviderInstallConfig): ProviderInstallOperation {
            check(SwingUtilities.isEventDispatchThread())
            return ProviderInstallOperation {
                check(!SwingUtilities.isEventDispatchThread())
                install(config)
            }
        }
    }

    private fun awaitOnEdt(
        timeoutSeconds: Long = 5,
        condition: () -> Boolean,
    ): Boolean {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(timeoutSeconds)
        while (System.nanoTime() < deadline) {
            val result = AtomicReference(false)
            SwingUtilities.invokeAndWait { result.set(condition()) }
            if (result.get()) return true
            Thread.sleep(10)
        }
        return false
    }

    private fun installConfig(token: String = SENTINEL_TOKEN, port: Int = 9876) =
        ProviderInstallConfig("127.0.0.1", port, token)

    private inline fun <reified T : Component> Container.findNamed(name: String): T =
        assertNotNull(findNamedOrNull(name))

    private inline fun <reified T : Component> Container.findNamedOrNull(name: String): T? {
        val matches = descendants().filterIsInstance<T>().filter { it.name == name }.toList()
        assertTrue(matches.size <= 1, "duplicate component name: $name")
        return matches.singleOrNull()
    }

    private fun Container.descendants(): Sequence<Component> = sequence {
        components.forEach { component ->
            yield(component)
            if (component is Container) yieldAll(component.descendants())
        }
    }

    private companion object {
        const val SENTINEL_TOKEN = "sentinel-current-bearer-token-value-000001x"
    }
}
