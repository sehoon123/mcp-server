package net.portswigger.mcp

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.BurpSuiteEdition
import burp.api.montoya.logging.Logging
import burp.api.montoya.persistence.PersistedObject
import burp.api.montoya.persistence.Preferences
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.presets.WorkflowPresetStore
import net.portswigger.mcp.security.NoOpMcpAuditSink
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertInstanceOf
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.util.concurrent.CountDownLatch
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

class KtorServerManagerLifecycleTest {
    private val bearerToken = "0123456789012345678901234567890123456789012"

    @Test
    fun `occupied listener reports the bind conflict and can be retried after cleanup`() {
        val occupied = ServerSocket().apply {
            reuseAddress = false
            bind(InetSocketAddress(InetAddress.getByName("127.0.0.1"), 0))
        }
        val logging = mockk<Logging>(relaxed = true)
        val manager = KtorServerManager(mockApi(logging))
        val states = LinkedBlockingQueue<ServerState>()
        val config = config(occupied.localPort, logging)
        try {
            manager.start(config, states::add)

            assertInstanceOf(ServerState.Starting::class.java, states.poll(5, TimeUnit.SECONDS))
            val failed = assertInstanceOf(ServerState.Failed::class.java, states.poll(10, TimeUnit.SECONDS))
            assertInstanceOf(McpServerStartupException::class.java, failed.exception)
            assertTrue(failed.exception.message.orEmpty().contains("127.0.0.1:${occupied.localPort} is already in use"))
            assertFalse(failed.exception.message.orEmpty().contains("LazyStandaloneCoroutine"))

            val failedDiagnostics = manager.diagnostics()
            assertEquals("failed", failedDiagnostics.state)
            assertTrue(failedDiagnostics.lastError.orEmpty().contains("already in use"))
            assertFalse(failedDiagnostics.lastError.orEmpty().contains("LazyStandaloneCoroutine"))
            verify {
                logging.logToError(match<String> {
                    it.contains("already in use") && !it.contains("LazyStandaloneCoroutine")
                })
            }

            occupied.close()
            states.clear()
            startAndAwaitRunning(manager, config, states)
            assertEquals(401, unauthenticatedPost(config.port))

            states.clear()
            manager.stop(states::add)
            assertInstanceOf(ServerState.Stopping::class.java, states.poll(5, TimeUnit.SECONDS))
            assertInstanceOf(ServerState.Stopped::class.java, states.poll(10, TimeUnit.SECONDS))
            assertEquals("stopped", manager.diagnostics().state)
        } finally {
            runCatching { occupied.close() }
            manager.shutdown()
        }
    }

    @Test
    fun `shutdown queued during startup leaves no listener or failed lifecycle state`() {
        val port = ServerSocket(0).use { it.localPort }
        val logging = mockk<Logging>(relaxed = true)
        val manager = KtorServerManager(mockApi(logging))
        val states = LinkedBlockingQueue<ServerState>()
        val config = config(port, logging)

        manager.start(config, states::add)
        manager.shutdown()

        assertEquals("stopped", manager.diagnostics().state)
        assertFalse(states.any { it is ServerState.Failed })
        ServerSocket().use { replacement ->
            replacement.reuseAddress = false
            replacement.bind(InetSocketAddress(InetAddress.getByName("127.0.0.1"), port))
        }
    }

    @Test
    fun `shutdown from lifecycle callback is nonblocking and repeated shutdown is a no-op`() {
        val port = ServerSocket(0).use { it.localPort }
        val logging = mockk<Logging>(relaxed = true)
        val manager = KtorServerManager(mockApi(logging))
        val states = LinkedBlockingQueue<ServerState>()
        val shutdownReturned = CountDownLatch(1)
        val config = config(port, logging)
        try {
            manager.start(config) { state ->
                states.add(state)
                if (state is ServerState.Running) {
                    manager.shutdown()
                    shutdownReturned.countDown()
                }
            }

            assertInstanceOf(ServerState.Starting::class.java, states.poll(5, TimeUnit.SECONDS))
            assertInstanceOf(ServerState.Running::class.java, states.poll(10, TimeUnit.SECONDS))
            assertTrue(shutdownReturned.await(5, TimeUnit.SECONDS))
            assertInstanceOf(ServerState.Stopped::class.java, states.poll(5, TimeUnit.SECONDS))
            assertEquals("stopped", manager.diagnostics().state)

            manager.shutdown()
            assertEquals("stopped", manager.diagnostics().state)
            ServerSocket().use { replacement ->
                replacement.reuseAddress = false
                replacement.bind(InetSocketAddress(InetAddress.getByName("127.0.0.1"), port))
            }
        } finally {
            manager.shutdown()
        }
    }

    @Test
    fun `interrupt insensitive stalled startup cannot publish after bounded shutdown`() {
        val port = ServerSocket(0).use { it.localPort }
        val logging = mockk<Logging>(relaxed = true)
        val api = mockApi(logging)
        val burpSuite = mockk<burp.api.montoya.burpsuite.BurpSuite>(relaxed = true)
        val version = mockk<burp.api.montoya.core.Version>(relaxed = true)
        every { version.edition() } returns BurpSuiteEdition.PROFESSIONAL
        every { burpSuite.version() } returns version
        val startupBlocked = CountDownLatch(1)
        val releaseStartup = AtomicBoolean()
        val startupWorker = AtomicReference<Thread?>()
        every { api.burpSuite() } answers {
            startupWorker.compareAndSet(null, Thread.currentThread())
            startupBlocked.countDown()
            while (!releaseStartup.get()) {
                try {
                    Thread.sleep(5)
                } catch (_: InterruptedException) {
                    // Exercise an integration call that does not cooperate with shutdownNow().
                }
            }
            burpSuite
        }
        val manager = KtorServerManager(
            api,
            NoOpMcpAuditSink,
            workflowPresetStore = WorkflowPresetStore(mockk<PersistedObject>(relaxed = true)),
            shutdownTimeoutMillis = 25,
        )
        val states = LinkedBlockingQueue<ServerState>()
        val shutdownThread = Thread(manager::shutdown)
        try {
            manager.start(config(port, logging), states::add)
            assertInstanceOf(ServerState.Starting::class.java, states.poll(5, TimeUnit.SECONDS))
            assertTrue(startupBlocked.await(5, TimeUnit.SECONDS))
            assertTrue(requireNotNull(startupWorker.get()).isDaemon)
            val startingMcpServerField = KtorServerManager::class.java.getDeclaredField("startingMcpServer").apply {
                isAccessible = true
            }
            assertTrue(startingMcpServerField.get(manager) != null)

            shutdownThread.start()
            shutdownThread.join(5_000)
            assertFalse(shutdownThread.isAlive)
            assertEquals("stopped", manager.diagnostics().state)
            assertEquals(null, startingMcpServerField.get(manager))
            ServerSocket().use { replacement ->
                replacement.bind(InetSocketAddress(InetAddress.getByName("127.0.0.1"), port))
            }

            releaseStartup.set(true)
            assertInstanceOf(ServerState.Stopped::class.java, states.poll(5, TimeUnit.SECONDS))
            assertFalse(states.any { it is ServerState.Running })
            ServerSocket().use { replacement ->
                replacement.bind(InetSocketAddress(InetAddress.getByName("127.0.0.1"), port))
            }
        } finally {
            releaseStartup.set(true)
            shutdownThread.join(5_000)
            manager.shutdown()
        }
    }

    @Test
    fun `start and stop after shutdown return terminal states without throwing`() {
        val port = ServerSocket(0).use { it.localPort }
        val logging = mockk<Logging>(relaxed = true)
        val manager = KtorServerManager(mockApi(logging))
        val states = LinkedBlockingQueue<ServerState>()

        manager.shutdown()
        manager.start(config(port, logging), states::add)
        assertInstanceOf(ServerState.Failed::class.java, states.poll(5, TimeUnit.SECONDS))
        manager.stop(states::add)
        assertInstanceOf(ServerState.Stopped::class.java, states.poll(5, TimeUnit.SECONDS))
        assertEquals("stopped", manager.diagnostics().state)
        verify(exactly = 0) { logging.logToError(match<String> { it.contains("shutdown failed") }) }
    }

    @Test
    fun `start stop start leaves one healthy listener and no failed state`() {
        val port = ServerSocket(0).use { it.localPort }
        val logging = mockk<Logging>(relaxed = true)
        val manager = KtorServerManager(mockApi(logging))
        val states = LinkedBlockingQueue<ServerState>()
        val config = config(port, logging)
        try {
            startAndAwaitRunning(manager, config, states)

            states.clear()
            manager.stop(states::add)
            assertInstanceOf(ServerState.Stopping::class.java, states.poll(5, TimeUnit.SECONDS))
            assertInstanceOf(ServerState.Stopped::class.java, states.poll(10, TimeUnit.SECONDS))

            states.clear()
            startAndAwaitRunning(manager, config, states)
            assertEquals(401, unauthenticatedPost(port))
            assertEquals("running", manager.diagnostics().state)
            assertFalse(states.any { it is ServerState.Failed })
        } finally {
            manager.shutdown()
        }
    }

    @Test
    fun `unreadable installation token preferences fail startup without opening a listener`() {
        val port = ServerSocket(0).use { it.localPort }
        val logging = mockk<Logging>(relaxed = true)
        val manager = KtorServerManager(mockApi(logging))
        val states = LinkedBlockingQueue<ServerState>()
        try {
            manager.start(config(port, logging, failTokenRead = true), states::add)

            assertInstanceOf(ServerState.Starting::class.java, states.poll(5, TimeUnit.SECONDS))
            assertInstanceOf(ServerState.Failed::class.java, states.poll(10, TimeUnit.SECONDS))
            assertEquals("failed", manager.diagnostics().state)
            ServerSocket().use { replacement ->
                replacement.reuseAddress = false
                replacement.bind(InetSocketAddress(InetAddress.getByName("127.0.0.1"), port))
            }
        } finally {
            manager.shutdown()
        }
    }

    private fun startAndAwaitRunning(
        manager: KtorServerManager,
        config: McpConfig,
        states: LinkedBlockingQueue<ServerState>,
    ) {
        manager.start(config, states::add)
        assertInstanceOf(ServerState.Starting::class.java, states.poll(5, TimeUnit.SECONDS))
        assertInstanceOf(ServerState.Running::class.java, states.poll(10, TimeUnit.SECONDS))
    }

    private fun unauthenticatedPost(port: Int): Int {
        val request = HttpRequest.newBuilder(URI("http://127.0.0.1:$port/mcp"))
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString("{}"))
            .build()
        return HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.discarding()).statusCode()
    }

    private fun mockApi(logging: Logging): MontoyaApi = mockk(relaxed = true) {
        every { this@mockk.logging() } returns logging
    }

    private fun config(port: Int, logging: Logging, failTokenRead: Boolean = false): McpConfig {
        val storage = mockk<PersistedObject>(relaxed = true)
        every { storage.getBoolean(any()) } returns true
        every { storage.getBoolean("approvalYoloMode") } returns false
        every { storage.getBoolean("emergencyReadOnlyMode") } returns false
        every { storage.getString(any()) } returns "127.0.0.1"
        every { storage.getInteger("port") } returns port
        val preferences = mockk<Preferences>(relaxed = true)
        if (failTokenRead) {
            every { preferences.getString("independentMcpBridge.localBearerToken.v1") } throws
                IllegalStateException("preferences unavailable")
        } else {
            every { preferences.getString("independentMcpBridge.localBearerToken.v1") } returns bearerToken
        }
        return McpConfig(storage, logging, preferences)
    }
}
