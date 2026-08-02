package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.persistence.PersistedObject
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.Mutex
import net.portswigger.mcp.presets.WorkflowPresetStore
import org.junit.jupiter.api.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertSame
import kotlin.test.assertTrue

class ToolServicesTest {
    @Test
    fun `project reset does not initialize unused lazy services`() = runBlocking {
        val api = mockk<MontoyaApi>(relaxed = true)
        val storage = mockk<PersistedObject>(relaxed = true)
        val store = WorkflowPresetStore(storage)
        val services = ToolServices(api, store)

        try {
            assertSame(store, services.workflowPresetStore)
            assertLazyServicesUninitialized(services)

            services.resetForProjectBoundary()

            assertLazyServicesUninitialized(services)
            verify(exactly = 0) { api.burpSuite() }
        } finally {
            services.close()
            services.close()
        }
    }

    @Test
    fun `close waits for an admitted project boundary reset`() {
        val api = mockk<MontoyaApi>(relaxed = true)
        val burpSuite = mockk<burp.api.montoya.burpsuite.BurpSuite>(relaxed = true)
        val version = mockk<burp.api.montoya.core.Version>(relaxed = true)
        every { version.edition() } returns burp.api.montoya.core.BurpSuiteEdition.COMMUNITY_EDITION
        every { burpSuite.version() } returns version
        val resetEntered = CountDownLatch(1)
        val releaseReset = CountDownLatch(1)
        every { api.burpSuite() } answers {
            resetEntered.countDown()
            releaseReset.await(5, TimeUnit.SECONDS)
            burpSuite
        }
        val services = ToolServices(
            api,
            WorkflowPresetStore(mockk<PersistedObject>(relaxed = true)),
        )
        services.collaborator
        val resetThread = Thread { runBlocking { services.resetForProjectBoundary() } }
        val closeThread = Thread(services::close)
        try {
            resetThread.start()
            assertEquals(true, resetEntered.await(5, TimeUnit.SECONDS))
            closeThread.start()
            closeThread.join(100)
            assertEquals(true, closeThread.isAlive)

            releaseReset.countDown()
            resetThread.join(5_000)
            closeThread.join(5_000)
            assertFalse(resetThread.isAlive)
            assertFalse(closeThread.isAlive)
            kotlin.test.assertFailsWith<IllegalStateException> { services.collaborator }
        } finally {
            releaseReset.countDown()
            resetThread.join(5_000)
            closeThread.join(5_000)
            services.close()
        }
    }

    @Test
    fun `close is bounded while an admitted reset defers final service cleanup`() {
        val api = mockk<MontoyaApi>(relaxed = true)
        val burpSuite = mockk<burp.api.montoya.burpsuite.BurpSuite>(relaxed = true)
        val version = mockk<burp.api.montoya.core.Version>(relaxed = true)
        every { version.edition() } returns burp.api.montoya.core.BurpSuiteEdition.COMMUNITY_EDITION
        every { burpSuite.version() } returns version
        val resetEntered = CountDownLatch(1)
        val releaseReset = CountDownLatch(1)
        every { api.burpSuite() } answers {
            resetEntered.countDown()
            releaseReset.await(5, TimeUnit.SECONDS)
            burpSuite
        }
        val services = ToolServices(
            api,
            WorkflowPresetStore(mockk<PersistedObject>(relaxed = true)),
            projectBoundaryCloseWaitMillis = 25,
        )
        services.collaborator
        val index = services.httpMetadataIndex
        val resetThread = Thread { runBlocking { services.resetForProjectBoundary() } }
        try {
            resetThread.start()
            assertTrue(resetEntered.await(5, TimeUnit.SECONDS))

            val startedAt = System.nanoTime()
            services.close()
            val elapsedMillis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startedAt)
            assertTrue(elapsedMillis < 1_000, "close took ${elapsedMillis}ms")
            assertTrue(resetThread.isAlive)
            kotlin.test.assertFailsWith<IllegalStateException> { services.collaborator }
            kotlin.test.assertFailsWith<IllegalStateException> {
                runBlocking { index.observeCurrentProject() }
            }

            releaseReset.countDown()
            resetThread.join(5_000)
            assertFalse(resetThread.isAlive)
            val closeClaimed = ToolServices::class.java.getDeclaredField("closeClaimed").apply {
                isAccessible = true
            }.get(services) as AtomicBoolean
            assertTrue(closeClaimed.get())
        } finally {
            releaseReset.countDown()
            resetThread.join(5_000)
            services.close()
        }
    }

    @Test
    fun `close is bounded while metadata index quiescence drains asynchronously`() {
        val services = ToolServices(
            mockk<MontoyaApi>(relaxed = true),
            WorkflowPresetStore(mockk<PersistedObject>(relaxed = true)),
            projectBoundaryCloseWaitMillis = 25,
        )
        val index = services.httpMetadataIndex
        val stateLock = HttpMetadataIndex::class.java.getDeclaredField("stateLock").apply {
            isAccessible = true
        }.get(index) as Mutex
        runBlocking { stateLock.lock() }
        try {
            val startedAt = System.nanoTime()
            services.close()
            val elapsedMillis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startedAt)
            assertTrue(elapsedMillis < 1_000, "close took ${elapsedMillis}ms")
            kotlin.test.assertFailsWith<IllegalStateException> { services.httpMetadataIndex }
        } finally {
            stateLock.unlock()
        }
        index.close()
    }

    @Test
    fun `close wins against a waiting lazy getter and prevents publication`() {
        val services = ToolServices(
            mockk<MontoyaApi>(relaxed = true),
            WorkflowPresetStore(mockk<PersistedObject>(relaxed = true)),
        )
        val lifecycleLock = ToolServices::class.java.getDeclaredField("lifecycleLock").apply {
            isAccessible = true
        }.get(services)
        val getterFailure = AtomicReference<Throwable?>()
        val getter = Thread {
            try {
                services.collaborator
            } catch (error: Throwable) {
                getterFailure.set(error)
            }
        }

        synchronized(lifecycleLock) {
            getter.start()
            val deadline = System.nanoTime() + 2_000_000_000L
            while (getter.state != Thread.State.BLOCKED && System.nanoTime() < deadline) Thread.yield()
            assertEquals(Thread.State.BLOCKED, getter.state)
            services.close()
        }
        getter.join(2_000)

        assertFalse(getter.isAlive)
        assertIs<IllegalStateException>(getterFailure.get())
        assertLazyServicesUninitialized(services)
        services.close()
    }

    private fun assertLazyServicesUninitialized(services: ToolServices) {
        listOf(
            "collaboratorDelegate",
            "scannerAuditsDelegate",
            "httpMetadataIndexDelegate",
            "httpSessionSecurityAnalyzerDelegate",
        ).forEach { fieldName ->
            val field = ToolServices::class.java.getDeclaredField(fieldName).apply { isAccessible = true }
            assertFalse((field.get(services) as Lazy<*>).isInitialized(), "$fieldName was initialized")
        }
    }
}
