package net.portswigger.mcp.tools

import com.sun.management.ThreadMXBean
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.lang.management.ManagementFactory
import java.nio.file.Files
import java.nio.file.Path
import java.util.RandomAccess
import java.util.UUID

private const val PROBE_WARMUP_ROUNDS = 3
private const val PROBE_MEASURED_ROUNDS = 9
private const val PROBE_PAGE_SIZE = 50
private val PROBE_SOURCE_SIZES = intArrayOf(10_000, 50_000, 100_000)

@Volatile
private var probeBlackhole: Any? = null

private data class SyntheticHistoryRecord(val id: Int)

private class SyntheticHistoryList(
    override val size: Int,
) : AbstractList<SyntheticHistoryRecord>(), RandomAccess {
    private val sharedRecord = SyntheticHistoryRecord(7)
    var getCalls: Long = 0
        private set

    override fun get(index: Int): SyntheticHistoryRecord {
        require(index in indices)
        getCalls++
        return sharedRecord
    }

    fun resetCounters() {
        getCalls = 0
    }
}

private data class ProbeSample(
    val allocatedBytes: Long,
    val indexedGets: Long,
    val checksum: Long,
)

@Serializable
private data class ProbeSummary(
    val schemaVersion: Int = 1,
    val measurementKind: String = "synthetic_allocation_and_accessor_diagnostic",
    val synthetic: Boolean = true,
    val source: String = "websocket_history_reference_list",
    val sourceSize: Int,
    val phase: String,
    val warmupRounds: Int,
    val measuredRounds: Int,
    val allocatedBytesSamples: List<Long>,
    val indexedGetsSamples: List<Long>,
    val checksum: Long,
    val runId: String,
    val sourceCommit: String,
    val sourceArchive: Boolean,
    val containerImage: String,
    val containerImageId: String,
    val containerMemoryLimit: String,
    val gradleVersion: String,
    val javaVersion: String,
    val vmName: String,
    val availableProcessors: Int,
    val maxHeapBytes: Long,
    val cpuModel: String,
    val osName: String,
    val osArch: String,
)

/**
 * Manual synthetic diagnostic. It measures current-thread allocation and reference-list access cardinality only; it
 * does not execute Burp, measure Montoya source-list acquisition, or produce latency benchmark evidence.
 */
fun main(args: Array<String>) {
    require(args.size == 1) { "expected one output JSONL path" }
    val sourceCommit = requiredEnvironment("SOURCE_COMMIT")
    require(sourceCommit.matches(Regex("[a-f0-9]{40}"))) { "SOURCE_COMMIT must be a full lowercase Git SHA" }
    require(requiredEnvironment("PROBE_SOURCE_ARCHIVE") == "true") {
        "the supported probe must execute an archive of SOURCE_COMMIT"
    }

    val allocationBean = (ManagementFactory.getThreadMXBean() as? ThreadMXBean)
        ?: error("com.sun.management.ThreadMXBean is unavailable")
    require(allocationBean.isThreadAllocatedMemorySupported) { "thread allocation measurement is unsupported" }
    if (!allocationBean.isThreadAllocatedMemoryEnabled) allocationBean.isThreadAllocatedMemoryEnabled = true

    val metadata = ProbeMetadata(
        runId = System.getenv("PROBE_RUN_ID")?.takeIf(String::isNotBlank) ?: UUID.randomUUID().toString(),
        sourceCommit = sourceCommit,
        containerImage = requiredEnvironment("PROBE_CONTAINER_IMAGE"),
        containerImageId = requiredEnvironment("PROBE_CONTAINER_IMAGE_ID"),
        containerMemoryLimit = requiredEnvironment("PROBE_CONTAINER_MEMORY"),
        gradleVersion = requiredEnvironment("PROBE_GRADLE_VERSION"),
    )
    val json = Json { encodeDefaults = true }
    val summaries = buildList {
        for (size in PROBE_SOURCE_SIZES) {
            val source = SyntheticHistoryList(size)
            add(measurePhase(source, "synthetic_supplier_only", metadata, allocationBean) {
                val acquired = source
                probeBlackhole = acquired
                System.identityHashCode(acquired).toLong()
            })
            add(measurePhase(source, "removed_extension_owned_full_copy_baseline", metadata, allocationBean) {
                val copied = source.toList()
                probeBlackhole = copied
                copied.size.toLong() * 31 + copied.first().id + copied.last().id
            })
            add(measurePhase(source, "bounded_reference_window_50", metadata, allocationBean) {
                var checksum = source.size.toLong()
                val first = source.first()
                val last = source.last()
                checksum = checksum * 31 + first.id
                checksum = checksum * 31 + last.id
                val window = ArrayList<SyntheticHistoryRecord>(minOf(PROBE_PAGE_SIZE, source.size))
                for (index in 0 until minOf(PROBE_PAGE_SIZE, source.size)) {
                    window += source[index]
                    checksum = checksum * 31 + window.last().id
                }
                for (index in window.indices) {
                    check(source[index] === window[index])
                    checksum = checksum * 31 + window[index].id
                }
                check(source.first() === first)
                check(source.last() === last)
                probeBlackhole = window
                checksum
            })
            val serializedResult = SearchWebsocketMessagesResult(
                status = WebSocketSearchStatus.OK,
                projectId = "synthetic-project",
                items = List(PROBE_PAGE_SIZE) { index ->
                    WebSocketHistorySummary(
                        id = index,
                        webSocketId = index / 5,
                        time = "2026-01-01T00:00:00Z",
                        direction = if (index and 1 == 0) "CLIENT_TO_SERVER" else "SERVER_TO_CLIENT",
                        payloadBytes = 128,
                        listenerPort = 8080,
                        notes = null,
                        notesTruncated = false,
                    )
                },
                returned = PROBE_PAGE_SIZE,
                scanned = PROBE_PAGE_SIZE,
            )
            add(measurePhase(source, "serialize_bounded_page_50", metadata, allocationBean) {
                val encoded = json.encodeToString(serializedResult)
                probeBlackhole = encoded
                encoded.length.toLong() * 31 + encoded.hashCode()
            })
        }
    }

    val destination = Path.of(args.single())
    destination.parent?.let { Files.createDirectories(it) }
    Files.writeString(destination, summaries.joinToString("\n") { json.encodeToString(it) } + "\n")
    println("Wrote ${summaries.size} synthetic diagnostic summaries to $destination")
}

private data class ProbeMetadata(
    val runId: String,
    val sourceCommit: String,
    val containerImage: String,
    val containerImageId: String,
    val containerMemoryLimit: String,
    val gradleVersion: String,
)

private fun measurePhase(
    source: SyntheticHistoryList,
    phase: String,
    metadata: ProbeMetadata,
    allocationBean: ThreadMXBean,
    operation: () -> Long,
): ProbeSummary {
    repeat(PROBE_WARMUP_ROUNDS) {
        source.resetCounters()
        operation()
    }

    val threadId = Thread.currentThread().threadId()
    val samples = List(PROBE_MEASURED_ROUNDS) {
        source.resetCounters()
        val allocatedBefore = allocationBean.getThreadAllocatedBytes(threadId)
        require(allocatedBefore >= 0) { "allocation counter was unavailable before phase $phase" }
        val checksum = operation()
        val allocatedAfter = allocationBean.getThreadAllocatedBytes(threadId)
        require(allocatedAfter >= allocatedBefore) { "allocation counter regressed during phase $phase" }
        ProbeSample(
            allocatedBytes = allocatedAfter - allocatedBefore,
            indexedGets = source.getCalls,
            checksum = checksum,
        )
    }
    val checksums = samples.map(ProbeSample::checksum).distinct()
    require(checksums.size == 1) { "phase $phase produced unstable checksums" }

    return ProbeSummary(
        sourceSize = source.size,
        phase = phase,
        warmupRounds = PROBE_WARMUP_ROUNDS,
        measuredRounds = PROBE_MEASURED_ROUNDS,
        allocatedBytesSamples = samples.map(ProbeSample::allocatedBytes),
        indexedGetsSamples = samples.map(ProbeSample::indexedGets),
        checksum = checksums.single(),
        runId = metadata.runId,
        sourceCommit = metadata.sourceCommit,
        sourceArchive = true,
        containerImage = metadata.containerImage,
        containerImageId = metadata.containerImageId,
        containerMemoryLimit = metadata.containerMemoryLimit,
        gradleVersion = metadata.gradleVersion,
        javaVersion = System.getProperty("java.version"),
        vmName = System.getProperty("java.vm.name"),
        availableProcessors = Runtime.getRuntime().availableProcessors(),
        maxHeapBytes = Runtime.getRuntime().maxMemory(),
        cpuModel = cpuModel(),
        osName = System.getProperty("os.name"),
        osArch = System.getProperty("os.arch"),
    )
}

private fun requiredEnvironment(name: String): String = requireNotNull(System.getenv(name)?.takeIf(String::isNotBlank)) {
    "$name must be set by the clean source-archive probe wrapper"
}

private fun cpuModel(): String = runCatching {
    Files.readAllLines(Path.of("/proc/cpuinfo")).firstNotNullOfOrNull { line ->
        val separator = line.indexOf(':')
        if (separator <= 0) return@firstNotNullOfOrNull null
        val key = line.substring(0, separator).trim()
        if (key != "model name" && key != "Hardware") return@firstNotNullOfOrNull null
        line.substring(separator + 1).trim().take(256)
    }
}.getOrNull().orEmpty().ifBlank { "unavailable" }
