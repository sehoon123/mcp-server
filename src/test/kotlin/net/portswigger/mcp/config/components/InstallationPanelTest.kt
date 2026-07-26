package net.portswigger.mcp.config.components

import io.mockk.every
import io.mockk.mockkObject
import io.mockk.unmockkObject
import io.mockk.verify
import net.portswigger.mcp.config.Dialogs
import net.portswigger.mcp.providers.Provider
import net.portswigger.mcp.providers.ProviderInstallConfig
import net.portswigger.mcp.providers.ProviderInstallOperation
import org.junit.jupiter.api.Test
import java.awt.Component
import java.awt.Container
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import javax.swing.JButton
import javax.swing.JPanel
import javax.swing.SwingUtilities
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class InstallationPanelTest {
    @Test
    fun `provider install captures one immutable snapshot and serializes duplicate clicks`() {
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
            null
        }
        var displayed = ProviderInstallConfig("127.0.0.1", 9876, "token-one")
        val notice = WarningLabel().apply { isVisible = true }
        lateinit var panel: InstallationPanel
        lateinit var button: JButton

        SwingUtilities.invokeAndWait {
            panel = InstallationPanel(listOf(provider), notice, JPanel()) { displayed }
            button = panel.findButton()
            button.doClick()
            button.doClick()
        }
        assertTrue(started.await(5, TimeUnit.SECONDS))
        displayed = ProviderInstallConfig("127.0.0.1", 9999, "token-two")
        SwingUtilities.invokeAndWait { assertFalse(button.isEnabled) }
        release.countDown()
        assertTrue(completed.await(5, TimeUnit.SECONDS))
        SwingUtilities.invokeAndWait { }

        assertEquals(1, calls.get())
        assertEquals(ProviderInstallConfig("127.0.0.1", 9876, "token-one"), installedConfig.get())
        SwingUtilities.invokeAndWait {
            assertTrue(button.isEnabled)
            assertFalse(notice.isVisible)
            panel.cleanup()
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
                "installed"
            }
            val notice = WarningLabel().apply { isVisible = true }
            lateinit var panel: InstallationPanel

            SwingUtilities.invokeAndWait {
                panel = InstallationPanel(listOf(provider), notice, JPanel()) {
                    ProviderInstallConfig("127.0.0.1", 9876, "token")
                }
                panel.findButton().doClick()
            }
            assertTrue(started.await(5, TimeUnit.SECONDS))
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

    private fun provider(install: (ProviderInstallConfig) -> String?): Provider = object : Provider {
        override val name = "Test Client"
        override val installButtonText = "Install Test Client"
        override val confirmationText: String? = null
        override fun prepareInstall(config: ProviderInstallConfig): ProviderInstallOperation {
            check(SwingUtilities.isEventDispatchThread())
            return ProviderInstallOperation {
                check(!SwingUtilities.isEventDispatchThread())
                install(config)
            }
        }
    }

    private fun Container.findButton(): JButton = descendants().filterIsInstance<JButton>().single()

    private fun Container.descendants(): Sequence<Component> = sequence {
        components.forEach { component ->
            yield(component)
            if (component is Container) yieldAll(component.descendants())
        }
    }
}
