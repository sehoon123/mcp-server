package net.portswigger.mcp.config

import java.awt.Desktop
import java.net.URI
import javax.swing.JButton

class Anchor(text: String, url: String) : JButton(text) {
    init {
        Design.enableKeyboardActivation(this)
        getAccessibleContext().accessibleName = text
        getAccessibleContext().accessibleDescription = "Opens $url in the default browser"
        addActionListener {
            try {
                if (Desktop.isDesktopSupported()) {
                    val desktop = Desktop.getDesktop()
                    if (desktop.isSupported(Desktop.Action.BROWSE)) desktop.browse(URI(url))
                }
            } catch (_: Exception) {
            }
        }
    }
}
