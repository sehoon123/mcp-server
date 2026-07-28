package net.portswigger.mcp.tools

import io.modelcontextprotocol.kotlin.sdk.server.ClientConnection
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.server.ServerOptions
import io.modelcontextprotocol.kotlin.sdk.types.CallToolRequest
import io.modelcontextprotocol.kotlin.sdk.types.CallToolRequestParams
import io.modelcontextprotocol.kotlin.sdk.types.Implementation
import io.modelcontextprotocol.kotlin.sdk.types.ServerCapabilities
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.util.concurrent.atomic.AtomicReference
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull

class McpStructuredToolSchedulingTest {
    private lateinit var server: Server
    private lateinit var connection: ClientConnection

    @BeforeEach
    fun setUp() {
        server = Server(
            serverInfo = Implementation("structured-scheduling-test", "1"),
            options = ServerOptions(capabilities = ServerCapabilities(tools = ServerCapabilities.Tools())),
        )
        connection = mockk(relaxed = true) {
            every { sessionId } returns "structured-scheduling-session"
        }
        SchedulingThreadProbe.reset()
    }

    @AfterEach
    fun tearDown() = runBlocking {
        server.close()
    }

    @Test
    fun `fallback structured JSON text and serialization stay on the bounded execution worker`() = runBlocking {
        server.mcpStructuredTool<StructuredSchedulingProbe, SchedulingProbeResult>(
            description = "structured scheduling probe",
            annotations = READ_ONLY_TOOL_ANNOTATIONS,
        ) {
            SchedulingThreadProbe.executionThread.set(Thread.currentThread())
            SchedulingProbeResult(value, 7)
        }

        val result = server.tools.getValue("structured_scheduling_probe").handler(
            connection,
            CallToolRequest(
                CallToolRequestParams(
                    "structured_scheduling_probe",
                    buildJsonObject { put("value", JsonPrimitive("fallback")) },
                )
            ),
        )

        assertEquals(false, result.isError)
        assertEquals(
            "{\"value\":\"fallback\",\"count\":7}",
            (result.content.single() as TextContent).text,
        )
        assertEquals("fallback", result.structuredContent?.get("value")?.toString()?.trim('"'))
        assertEquals("7", result.structuredContent?.get("count")?.toString())
        assertSameBoundedWorker()
    }

    @Test
    fun `explicit compatibility text and structured expected error retain their exact result contract`() = runBlocking {
        server.mcpStructuredToolWithContext<StructuredContextSchedulingProbe, SchedulingProbeResult>(
            description = "structured context scheduling probe",
            annotations = READ_ONLY_TOOL_ANNOTATIONS,
        ) { input ->
            SchedulingThreadProbe.executionThread.set(Thread.currentThread())
            StructuredToolResponse(
                output = SchedulingProbeResult(input.value, 9),
                text = "compatibility-text:${input.value}",
                isError = true,
            )
        }

        val result = server.tools.getValue("structured_context_scheduling_probe").handler(
            connection,
            CallToolRequest(
                CallToolRequestParams(
                    "structured_context_scheduling_probe",
                    buildJsonObject { put("value", JsonPrimitive("expected-error")) },
                )
            ),
        )

        assertEquals(true, result.isError)
        assertEquals(
            "compatibility-text:expected-error",
            (result.content.single() as TextContent).text,
        )
        assertEquals("expected-error", result.structuredContent?.get("value")?.toString()?.trim('"'))
        assertEquals("9", result.structuredContent?.get("count")?.toString())
        assertSameBoundedWorker()
    }

    private fun assertSameBoundedWorker() {
        val executionThread = assertNotNull(SchedulingThreadProbe.executionThread.get())
        val serializationThread = assertNotNull(SchedulingThreadProbe.serializationThread.get())
        assertEquals(executionThread, serializationThread)
        assertNotEquals(Thread.currentThread(), serializationThread)
    }
}

@Serializable
private data class StructuredSchedulingProbe(val value: String)

@Serializable
private data class StructuredContextSchedulingProbe(val value: String)

@Serializable(with = SchedulingProbeResultSerializer::class)
private data class SchedulingProbeResult(
    val value: String,
    val count: Int,
)

@Serializable
private data class SchedulingProbeSurrogate(
    val value: String,
    val count: Int,
)

private object SchedulingProbeResultSerializer : KSerializer<SchedulingProbeResult> {
    override val descriptor: SerialDescriptor = SchedulingProbeSurrogate.serializer().descriptor

    override fun serialize(encoder: Encoder, value: SchedulingProbeResult) {
        SchedulingThreadProbe.serializationThread.set(Thread.currentThread())
        encoder.encodeSerializableValue(
            SchedulingProbeSurrogate.serializer(),
            SchedulingProbeSurrogate(value.value, value.count),
        )
    }

    override fun deserialize(decoder: Decoder): SchedulingProbeResult {
        val value = decoder.decodeSerializableValue(SchedulingProbeSurrogate.serializer())
        return SchedulingProbeResult(value.value, value.count)
    }
}

private object SchedulingThreadProbe {
    val executionThread = AtomicReference<Thread?>()
    val serializationThread = AtomicReference<Thread?>()

    fun reset() {
        executionThread.set(null)
        serializationThread.set(null)
    }
}
