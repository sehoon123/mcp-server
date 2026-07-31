package net.portswigger.mcp

import burp.api.montoya.persistence.Preferences
import io.mockk.every
import io.mockk.mockk
import java.util.concurrent.ConcurrentHashMap

/** Installation-scoped string preferences for tests that do not exercise Montoya persistence itself. */
internal fun testPreferences(initialStrings: Map<String, String> = emptyMap()): Preferences {
    val strings = ConcurrentHashMap(initialStrings)
    return mockk(relaxed = true) {
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
