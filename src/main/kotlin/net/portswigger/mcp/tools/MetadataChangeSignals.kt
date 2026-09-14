package net.portswigger.mcp.tools

import java.util.concurrent.atomic.AtomicLongArray

internal enum class MetadataChangeSource {
    PROXY_HTTP,
    SITE_MAP,
    // Burp exposes no Organizer listener; MCP Organizer writes invalidate through HttpMetadataIndex.withMutation.
    ORGANIZER,
    WEBSOCKET,
    SCANNER_ISSUES,
}

/**
 * Fixed-cardinality, value-free source change signals.
 *
 * Traffic callbacks may only identify one compile-time source category. No callback object or traffic-derived value is
 * accepted or retained. Marks are constant-time, allocation-free, and become no-ops after close.
 */
internal class MetadataChangeSignals private constructor(
    enabled: Boolean,
) : AutoCloseable {
    constructor() : this(true)

    private val revisions = AtomicLongArray(MetadataChangeSource.entries.size).also { values ->
        if (!enabled) {
            for (index in 0 until values.length()) values.set(index, CLOSED_MASK)
        }
    }

    fun markChanged(source: MetadataChangeSource) {
        val index = source.ordinal
        while (true) {
            val current = revisions.get(index)
            if (current < 0 || current == Long.MAX_VALUE) return
            if (revisions.compareAndSet(index, current, current + 1)) return
        }
    }

    fun revision(source: MetadataChangeSource): Long = revisions.get(source.ordinal) and Long.MAX_VALUE

    override fun close() {
        for (index in 0 until revisions.length()) {
            while (true) {
                val current = revisions.get(index)
                if (current < 0 || revisions.compareAndSet(index, current, current or CLOSED_MASK)) break
            }
        }
    }

    companion object {
        private const val CLOSED_MASK = Long.MIN_VALUE
        val NO_OP = MetadataChangeSignals(false)
    }
}

internal fun HttpMessageSource.metadataChangeSource(): MetadataChangeSource = when (this) {
    HttpMessageSource.PROXY -> MetadataChangeSource.PROXY_HTTP
    HttpMessageSource.SITE_MAP -> MetadataChangeSource.SITE_MAP
    HttpMessageSource.ORGANIZER -> MetadataChangeSource.ORGANIZER
}
