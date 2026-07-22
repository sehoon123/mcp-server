package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.schema.JsonSchemaMetadata
import net.portswigger.mcp.security.DataAccessSecurity
import net.portswigger.mcp.security.DataAccessType
import net.portswigger.mcp.security.safeExceptionSummary

private const val DEFAULT_ATTACK_SURFACE_SERVICE_LIMIT = 25
private const val MAX_ATTACK_SURFACE_SERVICE_LIMIT = 100
private const val DEFAULT_ATTACK_SURFACE_PATH_LIMIT = 50
private const val MAX_ATTACK_SURFACE_PATH_LIMIT = 200
private const val DEFAULT_ATTACK_SURFACE_PATH_DEPTH = 2
private const val MAX_ATTACK_SURFACE_PATH_DEPTH = 4
private const val MAX_ATTACK_SURFACE_GLOBAL_COUNTS = 32
private const val MAX_ATTACK_SURFACE_SERVICE_COUNTS = 16
private const val MAX_ATTACK_SURFACE_PATH_COUNTS = 8
private const val MAX_ATTACK_SURFACE_SEGMENT_CHARS = 128
private const val MAX_ATTACK_SURFACE_PREFIX_CHARS = 512
private const val MAX_ATTACK_SURFACE_SNAPSHOT_ATTEMPTS = 2

@Serializable
data class SummarizeHttpAttackSurface(
    @JsonSchemaMetadata(description = "Current Burp project ID.", minLength = 1, maxLength = 256)
    val projectId: String,
    @JsonSchemaMetadata(
        description = "Approved stores to summarize. Defaults to Proxy only.",
        minItems = 1,
        maxItems = 3,
        defaultJson = "[\"proxy\"]",
    )
    val sources: List<HttpMessageSource>? = null,
    @JsonSchemaMetadata(description = "Only count messages currently classified as in scope.", defaultJson = "true")
    val inScopeOnly: Boolean? = null,
    @JsonSchemaMetadata(description = "Number of path segments retained in normalized prefixes.", minimum = 1, maximum = 4, defaultJson = "2")
    val pathDepth: Int? = null,
    @JsonSchemaMetadata(description = "Maximum service summaries returned.", minimum = 1, maximum = 100, defaultJson = "25")
    val serviceLimit: Int? = null,
    @JsonSchemaMetadata(description = "Maximum normalized path-prefix summaries returned.", minimum = 1, maximum = 200, defaultJson = "50")
    val pathLimit: Int? = null,
)

@Serializable
enum class HttpAttackSurfaceStatus {
    @SerialName("ok")
    OK,

    @SerialName("access_denied")
    ACCESS_DENIED,

    @SerialName("invalid_argument")
    INVALID_ARGUMENT,

    @SerialName("project_mismatch")
    PROJECT_MISMATCH,

    @SerialName("burp_error")
    BURP_ERROR,
}

@Serializable
data class AttackSurfaceCount(
    val value: String,
    val count: Int,
)

@Serializable
data class AttackSurfaceSourceStats(
    val source: HttpMessageSource,
    val totalRecords: Int,
    val indexedFrom: Int,
    val indexedRangeRecords: Int,
    val availableRecords: Int,
    val inScopeRecords: Int,
    val outOfScopeRecords: Int,
    val responseRecords: Int,
    val requestOnlyRecords: Int,
    val unavailableRecords: Int,
    val omittedRecords: Int,
    val refresh: MetadataIndexRefresh,
)

@Serializable
data class AttackSurfaceServiceSummary(
    val scheme: String,
    val host: String,
    val port: Int,
    val messageCount: Int,
    val responseCount: Int,
    val inScopeCount: Int,
    val outOfScopeCount: Int,
    val methods: List<AttackSurfaceCount>,
    val statusClasses: List<AttackSurfaceCount>,
    val mimeTypes: List<AttackSurfaceCount>,
    val extensions: List<AttackSurfaceCount>,
)

@Serializable
data class AttackSurfacePathSummary(
    val scheme: String,
    val host: String,
    val port: Int,
    val pathPrefix: String,
    val messageCount: Int,
    val responseCount: Int,
    val inScopeCount: Int,
    val outOfScopeCount: Int,
    val methods: List<AttackSurfaceCount>,
    val statusClasses: List<AttackSurfaceCount>,
)

@Serializable
data class HttpAttackSurfaceResult(
    val status: HttpAttackSurfaceStatus,
    val projectId: String?,
    val inScopeOnly: Boolean,
    val pathDepth: Int,
    val sources: List<AttackSurfaceSourceStats>,
    val indexedRangeRecords: Int,
    val availableRecords: Int,
    val availableInScopeRecords: Int,
    val availableOutOfScopeRecords: Int,
    val matchedRecords: Int,
    val responseRecords: Int,
    val requestOnlyRecords: Int,
    val serviceCount: Int,
    val servicesTruncated: Boolean,
    val services: List<AttackSurfaceServiceSummary>,
    val pathPrefixCount: Int,
    val pathPrefixesTruncated: Boolean,
    val pathPrefixes: List<AttackSurfacePathSummary>,
    val methods: List<AttackSurfaceCount>,
    val statusClasses: List<AttackSurfaceCount>,
    val mimeTypes: List<AttackSurfaceCount>,
    val extensions: List<AttackSurfaceCount>,
    val error: String? = null,
)

internal class HttpAttackSurfaceService(
    private val api: MontoyaApi,
    private val config: McpConfig,
    private val index: HttpMetadataIndex,
    private val beforeSnapshotValidation: suspend (attempt: Int) -> Unit = {},
) {
    suspend fun summarize(input: SummarizeHttpAttackSurface): HttpAttackSurfaceResult {
        val normalized = normalize(input) ?: return invalidResult(input)
        val currentProjectId = try {
            index.observeCurrentProject()
        } catch (_: HttpMetadataIndexChangingException) {
            return emptyResult(
                status = HttpAttackSurfaceStatus.BURP_ERROR,
                projectId = input.projectId,
                normalized = normalized,
                error = "HTTP metadata is changing; retry after the project update completes",
            )
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            return emptyResult(
                status = HttpAttackSurfaceStatus.BURP_ERROR,
                projectId = input.projectId,
                normalized = normalized,
                error = "Burp could not read the current project: ${safeExceptionSummary(e)}",
            )
        }
        if (currentProjectId != input.projectId) {
            return emptyResult(
                status = HttpAttackSurfaceStatus.PROJECT_MISMATCH,
                projectId = currentProjectId,
                normalized = normalized,
                error = "The requested HTTP metadata belongs to a different Burp project",
            )
        }

        for (source in normalized.sources) {
            val allowed = try {
                DataAccessSecurity.checkDataAccessPermission(source.toDataAccessType(), config)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                return emptyResult(
                    status = HttpAttackSurfaceStatus.BURP_ERROR,
                    projectId = input.projectId,
                    normalized = normalized,
                    error = "Burp could not check HTTP metadata access: ${safeExceptionSummary(e)}",
                )
            }
            if (!allowed) {
                try {
                    api.logging().logToOutput("MCP HTTP attack-surface access denied for ${source.name.lowercase()}")
                } catch (e: CancellationException) {
                    throw e
                } catch (_: Exception) {
                    // Logging must not change the access-denied result.
                }
                return emptyResult(
                    status = HttpAttackSurfaceStatus.ACCESS_DENIED,
                    projectId = input.projectId,
                    normalized = normalized,
                    error = "${source.name.lowercase()} access denied by Burp Suite",
                )
            }
        }

        for (attempt in 0 until MAX_ATTACK_SURFACE_SNAPSHOT_ATTEMPTS) {
            val snapshot = try {
                index.snapshot(input.projectId, normalized.sources)
            } catch (e: HttpMetadataProjectMismatchException) {
                return emptyResult(
                    status = HttpAttackSurfaceStatus.PROJECT_MISMATCH,
                    projectId = e.currentProjectId,
                    normalized = normalized,
                    error = "Burp project changed before the HTTP metadata summary was returned",
                )
            } catch (_: HttpMetadataIndexChangingException) {
                return emptyResult(
                    status = HttpAttackSurfaceStatus.BURP_ERROR,
                    projectId = input.projectId,
                    normalized = normalized,
                    error = "HTTP metadata is changing; retry after the project update completes",
                )
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                return emptyResult(
                    status = HttpAttackSurfaceStatus.BURP_ERROR,
                    projectId = input.projectId,
                    normalized = normalized,
                    error = "Burp could not refresh the HTTP metadata index: ${safeExceptionSummary(e)}",
                )
            }

            val result = aggregate(snapshot, normalized)
            val snapshotIsCurrent = try {
                beforeSnapshotValidation(attempt)
                index.isSnapshotCurrent(snapshot)
            } catch (e: HttpMetadataProjectMismatchException) {
                return emptyResult(
                    status = HttpAttackSurfaceStatus.PROJECT_MISMATCH,
                    projectId = e.currentProjectId,
                    normalized = normalized,
                    error = "Burp project changed before the HTTP metadata summary was returned",
                )
            } catch (_: HttpMetadataIndexChangingException) {
                return emptyResult(
                    status = HttpAttackSurfaceStatus.BURP_ERROR,
                    projectId = input.projectId,
                    normalized = normalized,
                    error = "HTTP metadata is changing; retry after the project update completes",
                )
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                return emptyResult(
                    status = HttpAttackSurfaceStatus.BURP_ERROR,
                    projectId = input.projectId,
                    normalized = normalized,
                    error = "Burp could not verify the HTTP metadata snapshot: ${safeExceptionSummary(e)}",
                )
            }
            if (snapshotIsCurrent) return result
        }

        return emptyResult(
            status = HttpAttackSurfaceStatus.BURP_ERROR,
            projectId = input.projectId,
            normalized = normalized,
            error = "HTTP metadata changed repeatedly while the summary was being prepared; retry the read",
        )
    }

    private suspend fun aggregate(
        snapshot: HttpMetadataIndexSnapshot,
        normalized: NormalizedAttackSurfaceInput,
    ): HttpAttackSurfaceResult {
        // Count all keys first, then build detailed counters only for keys that can be returned. This preserves exact
        // rankings while avoiding four nested maps for every one-off service and path in adversarial histories.
        val serviceCounts = linkedMapOf<ServiceKey, Int>()
        val pathCounts = linkedMapOf<PathKey, Int>()
        val methods = HashMap<String, Int>()
        val statusClasses = HashMap<String, Int>()
        val mimeTypes = HashMap<String, Int>()
        val extensions = HashMap<String, Int>()
        val preparedRecords = ArrayList<PreparedAttackSurfaceRecord>(snapshot.sources.sumOf { it.slots.size })
        val sourceStats = ArrayList<AttackSurfaceSourceStats>(snapshot.sources.size)
        var matchedRecords = 0
        var responseRecords = 0
        var inspected = 0
        val coroutineContext = currentCoroutineContext()

        for (source in snapshot.sources) {
            var availableForSource = 0
            var inScopeForSource = 0
            var responsesForSource = 0
            var unavailableForSource = 0
            for (record in source.slots) {
                if (inspected++ and 255 == 0) coroutineContext.ensureActive()
                if (record == null) {
                    unavailableForSource++
                    continue
                }
                availableForSource++
                if (record.inScope) inScopeForSource++
                if (record.hasResponse) responsesForSource++
                if (normalized.inScopeOnly && !record.inScope) continue

                matchedRecords++
                if (record.hasResponse) responseRecords++
                val recordStatusClass = record.statusCode?.let(::statusClass)
                val recordMimeType = record.mimeType?.lowercase()
                val recordExtension = fileExtension(record)
                increment(methods, record.method)
                recordStatusClass?.let { increment(statusClasses, it) }
                recordMimeType?.let { increment(mimeTypes, it) }
                recordExtension?.let { increment(extensions, it) }

                val serviceKey = ServiceKey(record.scheme, record.host, record.port)
                val pathKey = PathKey(
                    service = serviceKey,
                    prefix = normalizedPathPrefix(record.path, normalized.pathDepth),
                )
                increment(serviceCounts, serviceKey)
                increment(pathCounts, pathKey)
                preparedRecords += PreparedAttackSurfaceRecord(
                    record = record,
                    serviceKey = serviceKey,
                    pathKey = pathKey,
                    statusClass = recordStatusClass,
                    mimeType = recordMimeType,
                    extension = recordExtension,
                )
            }
            sourceStats += AttackSurfaceSourceStats(
                source = source.source,
                totalRecords = source.totalRecords,
                indexedFrom = source.indexedFrom,
                indexedRangeRecords = source.slots.size,
                availableRecords = availableForSource,
                inScopeRecords = inScopeForSource,
                outOfScopeRecords = availableForSource - inScopeForSource,
                responseRecords = responsesForSource,
                requestOnlyRecords = availableForSource - responsesForSource,
                unavailableRecords = unavailableForSource,
                omittedRecords = source.omittedRecords,
                refresh = source.refresh,
            )
        }

        val selectedServiceKeys = serviceCounts.entries
            .sortedWith(
                compareByDescending<Map.Entry<ServiceKey, Int>> { it.value }
                    .thenBy { it.key.host }
                    .thenBy { it.key.port }
                    .thenBy { it.key.scheme }
            )
            .take(normalized.serviceLimit)
            .map(Map.Entry<ServiceKey, Int>::key)
        val selectedPathKeys = pathCounts.entries
            .sortedWith(
                compareByDescending<Map.Entry<PathKey, Int>> { it.value }
                    .thenBy { it.key.service.host }
                    .thenBy { it.key.service.port }
                    .thenBy { it.key.prefix }
            )
            .take(normalized.pathLimit)
            .map(Map.Entry<PathKey, Int>::key)
        val serviceAggregates = selectedServiceKeys.associateWithTo(HashMap()) { MutableServiceAggregate() }
        val pathAggregates = selectedPathKeys.associateWithTo(HashMap()) { MutablePathAggregate() }

        for ((index, prepared) in preparedRecords.withIndex()) {
            if (index and 255 == 0) coroutineContext.ensureActive()
            serviceAggregates[prepared.serviceKey]?.add(prepared)
            pathAggregates[prepared.pathKey]?.add(prepared)
        }

        val serviceResults = selectedServiceKeys.map { key -> serviceAggregates.getValue(key).toSummary(key) }
        val pathResults = selectedPathKeys.map { key -> pathAggregates.getValue(key).toSummary(key) }

        return HttpAttackSurfaceResult(
            status = HttpAttackSurfaceStatus.OK,
            projectId = snapshot.projectId,
            inScopeOnly = normalized.inScopeOnly,
            pathDepth = normalized.pathDepth,
            sources = sourceStats,
            indexedRangeRecords = sourceStats.sumOf { it.indexedRangeRecords },
            availableRecords = sourceStats.sumOf { it.availableRecords },
            availableInScopeRecords = sourceStats.sumOf { it.inScopeRecords },
            availableOutOfScopeRecords = sourceStats.sumOf { it.outOfScopeRecords },
            matchedRecords = matchedRecords,
            responseRecords = responseRecords,
            requestOnlyRecords = matchedRecords - responseRecords,
            serviceCount = serviceCounts.size,
            servicesTruncated = serviceCounts.size > serviceResults.size,
            services = serviceResults,
            pathPrefixCount = pathCounts.size,
            pathPrefixesTruncated = pathCounts.size > pathResults.size,
            pathPrefixes = pathResults,
            methods = methods.topCounts(MAX_ATTACK_SURFACE_GLOBAL_COUNTS),
            statusClasses = statusClasses.topCounts(MAX_ATTACK_SURFACE_GLOBAL_COUNTS),
            mimeTypes = mimeTypes.topCounts(MAX_ATTACK_SURFACE_GLOBAL_COUNTS),
            extensions = extensions.topCounts(MAX_ATTACK_SURFACE_GLOBAL_COUNTS),
        )
    }

    private fun normalize(input: SummarizeHttpAttackSurface): NormalizedAttackSurfaceInput? {
        if (input.projectId.isBlank() || input.projectId.length > 256 || input.projectId.any(Char::isISOControl)) {
            return null
        }
        val sources = input.sources ?: listOf(HttpMessageSource.PROXY)
        if (sources.isEmpty() || sources.size > 3 || sources.distinct().size != sources.size) return null
        val pathDepth = input.pathDepth ?: DEFAULT_ATTACK_SURFACE_PATH_DEPTH
        val serviceLimit = input.serviceLimit ?: DEFAULT_ATTACK_SURFACE_SERVICE_LIMIT
        val pathLimit = input.pathLimit ?: DEFAULT_ATTACK_SURFACE_PATH_LIMIT
        if (pathDepth !in 1..MAX_ATTACK_SURFACE_PATH_DEPTH) return null
        if (serviceLimit !in 1..MAX_ATTACK_SURFACE_SERVICE_LIMIT) return null
        if (pathLimit !in 1..MAX_ATTACK_SURFACE_PATH_LIMIT) return null
        return NormalizedAttackSurfaceInput(
            sources = sources.sortedBy(HttpMessageSource::ordinal),
            inScopeOnly = input.inScopeOnly ?: true,
            pathDepth = pathDepth,
            serviceLimit = serviceLimit,
            pathLimit = pathLimit,
        )
    }

    private fun invalidResult(input: SummarizeHttpAttackSurface): HttpAttackSurfaceResult = emptyResult(
        status = HttpAttackSurfaceStatus.INVALID_ARGUMENT,
        projectId = input.projectId.takeIf {
            it.isNotBlank() && it.length <= 256 && it.none(Char::isISOControl)
        },
        normalized = NormalizedAttackSurfaceInput(
            sources = emptyList(),
            inScopeOnly = input.inScopeOnly ?: true,
            pathDepth = (input.pathDepth ?: DEFAULT_ATTACK_SURFACE_PATH_DEPTH)
                .coerceIn(1, MAX_ATTACK_SURFACE_PATH_DEPTH),
            serviceLimit = DEFAULT_ATTACK_SURFACE_SERVICE_LIMIT,
            pathLimit = DEFAULT_ATTACK_SURFACE_PATH_LIMIT,
        ),
        error = "projectId, sources, pathDepth, serviceLimit, or pathLimit is invalid",
    )

    private fun emptyResult(
        status: HttpAttackSurfaceStatus,
        projectId: String?,
        normalized: NormalizedAttackSurfaceInput,
        error: String,
    ) = HttpAttackSurfaceResult(
        status = status,
        projectId = projectId,
        inScopeOnly = normalized.inScopeOnly,
        pathDepth = normalized.pathDepth,
        sources = emptyList(),
        indexedRangeRecords = 0,
        availableRecords = 0,
        availableInScopeRecords = 0,
        availableOutOfScopeRecords = 0,
        matchedRecords = 0,
        responseRecords = 0,
        requestOnlyRecords = 0,
        serviceCount = 0,
        servicesTruncated = false,
        services = emptyList(),
        pathPrefixCount = 0,
        pathPrefixesTruncated = false,
        pathPrefixes = emptyList(),
        methods = emptyList(),
        statusClasses = emptyList(),
        mimeTypes = emptyList(),
        extensions = emptyList(),
        error = error,
    )
}

private data class NormalizedAttackSurfaceInput(
    val sources: List<HttpMessageSource>,
    val inScopeOnly: Boolean,
    val pathDepth: Int,
    val serviceLimit: Int,
    val pathLimit: Int,
)

private data class ServiceKey(val scheme: String, val host: String, val port: Int)
private data class PathKey(val service: ServiceKey, val prefix: String)

private data class PreparedAttackSurfaceRecord(
    val record: HttpMetadataRecord,
    val serviceKey: ServiceKey,
    val pathKey: PathKey,
    val statusClass: String?,
    val mimeType: String?,
    val extension: String?,
)

private class MutableServiceAggregate {
    private var messageCount = 0
    private var responseCount = 0
    private var inScopeCount = 0
    private val methods = HashMap<String, Int>()
    private val statusClasses = HashMap<String, Int>()
    private val mimeTypes = HashMap<String, Int>()
    private val extensions = HashMap<String, Int>()

    fun add(prepared: PreparedAttackSurfaceRecord) {
        val record = prepared.record
        messageCount++
        if (record.hasResponse) responseCount++
        if (record.inScope) inScopeCount++
        increment(methods, record.method)
        prepared.statusClass?.let { increment(statusClasses, it) }
        prepared.mimeType?.let { increment(mimeTypes, it) }
        prepared.extension?.let { increment(extensions, it) }
    }

    fun toSummary(key: ServiceKey) = AttackSurfaceServiceSummary(
        scheme = key.scheme,
        host = key.host,
        port = key.port,
        messageCount = messageCount,
        responseCount = responseCount,
        inScopeCount = inScopeCount,
        outOfScopeCount = messageCount - inScopeCount,
        methods = methods.topCounts(MAX_ATTACK_SURFACE_SERVICE_COUNTS),
        statusClasses = statusClasses.topCounts(MAX_ATTACK_SURFACE_SERVICE_COUNTS),
        mimeTypes = mimeTypes.topCounts(MAX_ATTACK_SURFACE_SERVICE_COUNTS),
        extensions = extensions.topCounts(MAX_ATTACK_SURFACE_SERVICE_COUNTS),
    )
}

private class MutablePathAggregate {
    private var messageCount = 0
    private var responseCount = 0
    private var inScopeCount = 0
    private val methods = HashMap<String, Int>()
    private val statusClasses = HashMap<String, Int>()

    fun add(prepared: PreparedAttackSurfaceRecord) {
        val record = prepared.record
        messageCount++
        if (record.hasResponse) responseCount++
        if (record.inScope) inScopeCount++
        increment(methods, record.method)
        prepared.statusClass?.let { increment(statusClasses, it) }
    }

    fun toSummary(key: PathKey) = AttackSurfacePathSummary(
        scheme = key.service.scheme,
        host = key.service.host,
        port = key.service.port,
        pathPrefix = key.prefix,
        messageCount = messageCount,
        responseCount = responseCount,
        inScopeCount = inScopeCount,
        outOfScopeCount = messageCount - inScopeCount,
        methods = methods.topCounts(MAX_ATTACK_SURFACE_PATH_COUNTS),
        statusClasses = statusClasses.topCounts(MAX_ATTACK_SURFACE_PATH_COUNTS),
    )
}

private fun HttpMessageSource.toDataAccessType(): DataAccessType = when (this) {
    HttpMessageSource.PROXY -> DataAccessType.HTTP_HISTORY
    HttpMessageSource.SITE_MAP -> DataAccessType.SITE_MAP
    HttpMessageSource.ORGANIZER -> DataAccessType.ORGANIZER
}

private fun normalizedPathPrefix(path: String, depth: Int): String {
    val queryStart = path.indexOf('?').takeIf { it >= 0 } ?: path.length
    val fragmentStart = path.indexOf('#').takeIf { it >= 0 } ?: path.length
    val pathEnd = minOf(queryStart, fragmentStart)
    val prefix = StringBuilder(minOf(pathEnd, MAX_ATTACK_SURFACE_PREFIX_CHARS))
    var cursor = 0
    var segments = 0
    while (cursor < pathEnd && segments < depth) {
        while (cursor < pathEnd && path[cursor] == '/') cursor++
        if (cursor >= pathEnd) break
        val nextSlash = path.indexOf('/', cursor).let { if (it < 0 || it > pathEnd) pathEnd else it }
        if (nextSlash > cursor) {
            prefix.append('/').append(normalizePathSegment(path.substring(cursor, nextSlash)))
            segments++
        }
        cursor = nextSlash + 1
    }
    if (segments == 0) return "/"
    return prefix.toString().take(MAX_ATTACK_SURFACE_PREFIX_CHARS)
}

private fun normalizePathSegment(raw: String): String {
    val segment = raw.take(MAX_ATTACK_SURFACE_SEGMENT_CHARS)
    return when {
        segment.isAsciiNumber() -> "{number}"
        segment.isUuid() -> "{uuid}"
        segment.isLongHex() || segment.isLongToken() -> "{id}"
        else -> segment
    }
}

private fun String.isAsciiNumber(): Boolean = isNotEmpty() && all { it in '0'..'9' }

private fun String.isUuid(): Boolean {
    if (length != 36) return false
    for (index in indices) {
        val character = this[index]
        when (index) {
            8, 13, 18, 23 -> if (character != '-') return false
            14 -> if (character !in '1'..'5') return false
            19 -> if (character.lowercaseChar() !in "89ab") return false
            else -> if (!character.isAsciiHex()) return false
        }
    }
    return true
}

private fun String.isLongHex(): Boolean = length >= 16 && all(Char::isAsciiHex)

private fun String.isLongToken(): Boolean = length >= 24 && all {
    it.isAsciiAlphanumeric() || it == '_' || it == '-'
}

private fun Char.isAsciiHex(): Boolean = this in '0'..'9' || this in 'a'..'f' || this in 'A'..'F'

private fun Char.isAsciiAlphanumeric(): Boolean = this in '0'..'9' || this in 'a'..'z' || this in 'A'..'Z'

private fun fileExtension(record: HttpMetadataRecord): String? {
    if (record.pathTruncated) return null
    val fileName = record.path.substringAfterLast('/')
    if (fileName.startsWith('.') || '.' !in fileName) return null
    return fileName.substringAfterLast('.')
        .takeIf { it.length in 1..16 && it.all(Char::isAsciiAlphanumeric) }
        ?.lowercase()
}

private fun statusClass(statusCode: Int): String = when (statusCode) {
    in 100..199 -> "1xx"
    in 200..299 -> "2xx"
    in 300..399 -> "3xx"
    in 400..499 -> "4xx"
    in 500..599 -> "5xx"
    else -> "other"
}

private fun <K> increment(target: MutableMap<K, Int>, key: K) {
    target[key] = (target[key] ?: 0) + 1
}

private fun Map<String, Int>.topCounts(limit: Int): List<AttackSurfaceCount> = entries
    .sortedWith(compareByDescending<Map.Entry<String, Int>> { it.value }.thenBy { it.key })
    .take(limit)
    .map { AttackSurfaceCount(it.key, it.value) }
