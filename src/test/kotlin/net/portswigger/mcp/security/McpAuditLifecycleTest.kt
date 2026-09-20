package net.portswigger.mcp.security

import burp.api.montoya.logging.Logging
import burp.api.montoya.persistence.PersistedObject
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import net.portswigger.mcp.config.McpConfig
import org.junit.jupiter.api.Test
import java.io.IOException
import java.util.concurrent.Future
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class McpAuditLifecycleTest {
    @Test
    fun `interrupted flush preserves caller interrupt status without shutting down the writer`() {
        val fixture = Fixture()
        val log = fixture.open()
        every { fixture.flushResult.get(5, TimeUnit.SECONDS) } throws InterruptedException("private-sentinel")
        assertFalse(Thread.currentThread().isInterrupted)
        try {
            log.flush()

            assertTrue(Thread.currentThread().isInterrupted)
            verify(exactly = 0) { fixture.writer.shutdownNow() }
            verify { fixture.logging.logToError("MCP audit flush failed: InterruptedException") }
        } finally {
            Thread.interrupted()
            every { fixture.flushResult.get(5, TimeUnit.SECONDS) } returns Unit
            log.close()
        }
    }

    @Test
    fun `interrupted close still shuts down when error logging fails and remains idempotent`() {
        val fixture = Fixture()
        val log = fixture.open()
        every { fixture.flushResult.get(5, TimeUnit.SECONDS) } throws InterruptedException("private-sentinel")
        every { fixture.logging.logToError(any<String>()) } throws IllegalStateException("logger unavailable")
        assertFalse(Thread.currentThread().isInterrupted)
        try {
            log.close()

            assertTrue(Thread.currentThread().isInterrupted)
            verify(exactly = 1) { fixture.writer.shutdownNow() }
            verify(exactly = 1) { fixture.logging.logToError("MCP audit close failed: InterruptedException") }
            log.close()
            log.flush()
            verify(exactly = 1) { fixture.writer.submit(any<Runnable>()) }
            verify(exactly = 1) { fixture.writer.shutdownNow() }
        } finally {
            Thread.interrupted()
        }
    }

    @Test
    fun `submission and shutdown failures cannot escape through a failed logger`() {
        val fixture = Fixture()
        val log = fixture.open()
        every { fixture.writer.submit(any<Runnable>()) } throws RejectedExecutionException("private-sentinel")
        every { fixture.writer.shutdownNow() } throws IllegalStateException("private-sentinel")
        every { fixture.logging.logToError(any<String>()) } throws IllegalStateException("logger unavailable")

        log.close()

        verify(exactly = 1) { fixture.writer.shutdownNow() }
        verify(exactly = 1) { fixture.logging.logToError("MCP audit close failed: RejectedExecutionException") }
        verify(exactly = 1) { fixture.logging.logToError("MCP audit shutdown failed: IllegalStateException") }
    }

    @Test
    fun `audit storage and logging unavailability do not abort construction or cleanup`() {
        val fixture = Fixture()
        every { fixture.storage.getString("redactedAuditV1") } throws IOException("private-sentinel")
        every { fixture.logging.logToError(any<String>()) } throws IllegalStateException("logger unavailable")

        fixture.open().use { log -> assertEquals(0, log.size()) }

        verify(exactly = 1) { fixture.logging.logToError("MCP audit load failed: IOException") }
        verify(exactly = 1) { fixture.writer.shutdownNow() }
    }

    @Test
    fun `invalid and oversized stored audit documents remain ignored when logging fails`() {
        listOf("not-json", "x".repeat(1024 * 1024 + 1)).forEach { raw ->
            val fixture = Fixture()
            every { fixture.storage.getString("redactedAuditV1") } returns raw
            every { fixture.logging.logToError(any<String>()) } throws IllegalStateException("logger unavailable")

            fixture.open().use { log -> assertEquals(0, log.size()) }

            verify(exactly = 1) { fixture.logging.logToError(any<String>()) }
            verify(exactly = 1) { fixture.writer.shutdownNow() }
        }
    }

    private class Fixture {
        val storage = mockk<PersistedObject>(relaxed = true)
        val config = mockk<McpConfig>(relaxed = true)
        val logging = mockk<Logging>(relaxed = true)
        val writer = mockk<ScheduledExecutorService>(relaxed = true)
        val flushResult = mockk<Future<Unit>>()

        init {
            every { storage.getString("redactedAuditV1") } returns null
            every { writer.submit(any<Runnable>()) } returns flushResult
            every { flushResult.get(5, TimeUnit.SECONDS) } returns Unit
        }

        fun open() = PersistentMcpAuditLog(storage, config, logging, writer = writer)
    }
}
