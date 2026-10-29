package net.portswigger.mcp

import burp.api.montoya.persistence.Preferences
import io.mockk.every
import io.mockk.mockk
import java.util.concurrent.ConcurrentHashMap

/** In-memory installation preferences for tests that do not exercise Montoya persistence itself. */
internal fun testPreferences(initialStrings: Map<String, String> = emptyMap()): Preferences {
    val strings = ConcurrentHashMap(initialStrings)
    val booleans = ConcurrentHashMap<String, Boolean>()
    val integers = ConcurrentHashMap<String, Int>()
    return mockk(relaxed = true) {
        every { getBoolean(any()) } answers { booleans[firstArg()] }
        every { setBoolean(any(), any()) } answers { booleans[firstArg()] = secondArg() }
        every { getInteger(any()) } answers { integers[firstArg()] }
        every { setInteger(any(), any()) } answers { integers[firstArg()] = secondArg() }
        every { getString(any()) } answers { strings[firstArg()] }
        every { setString(any(), any()) } answers {
            strings[firstArg()] = secondArg()
        }
        every { deleteString(any()) } answers {
            strings.remove(firstArg())
            Unit
        }
    }
}
