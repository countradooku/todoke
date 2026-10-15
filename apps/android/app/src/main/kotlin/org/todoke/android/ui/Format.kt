// Text for people: sizes, fingerprints, and what a peer-chosen name is.
// Names arrive escaped by the core (bidi and invisible characters shown as
// \u{...}); the extension is kept apart so shortening never hides it.

package org.todoke.android.ui

import java.util.Locale
import org.todoke.ffi.Entry

object Format {
    fun bytes(count: Long): String {
        val units = listOf("B", "KB", "MB", "GB", "TB")
        var value = count.toDouble()
        var unit = 0
        while (value >= 1000 && unit < units.lastIndex) {
            value /= 1000
            unit++
        }
        return if (unit == 0) "$count B" else String.format(Locale.ROOT, "%.1f %s", value, units[unit])
    }

    /** A fingerprint in groups of four, for comparing by eye. */
    fun fingerprint(hex: String): String = hex.take(16).chunked(4).joinToString(" ").uppercase(Locale.ROOT)

    /** The name split before its last extension (at most 16 characters). */
    fun nameParts(name: String): Pair<String, String> {
        val dot = name.lastIndexOf('.')
        val extension = if (dot > 0) name.substring(dot + 1) else ""
        return if (extension.isNotEmpty() && extension.length <= 16) {
            name.substring(0, dot) to ".$extension"
        } else {
            name to ""
        }
    }

    /** Whether an entry is something a system runs, by name or by claimed
     * type (the same lists as the desktop app). */
    fun isProgram(entry: Entry): Boolean {
        if (entry.directory) return false
        val extension = entry.name.substringAfterLast('.', "").lowercase(Locale.ROOT)
        return extension in PROGRAMS || entry.mime.lowercase(Locale.ROOT) in PROGRAM_TYPES
    }

    private val PROGRAMS = setOf(
        "exe", "msi", "msix", "appx", "bat", "cmd", "com", "scr", "pif", "cpl", "dll", "sys", "ps1", "psm1",
        "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "reg", "lnk", "url", "inf", "jar", "app", "pkg",
        "command", "tool", "workflow", "scpt", "applescript", "dylib", "sh", "bash", "zsh", "csh", "fish", "py",
        "pyw", "pl", "rb", "php", "lua", "apk", "deb", "rpm", "appimage", "flatpakref", "snap", "desktop", "run",
        "elf", "html", "htm", "xhtml", "svg", "docm", "dotm", "xlsm", "xltm", "xlam", "pptm", "potm", "ppam",
        "sldm",
    )

    private val PROGRAM_TYPES = setOf(
        "application/x-sh", "application/x-shellscript", "text/x-shellscript", "application/x-executable",
        "application/x-elf", "application/x-mach-binary", "application/x-msdownload", "application/x-msdos-program",
        "application/x-msi", "application/vnd.microsoft.portable-executable", "application/java-archive",
        "application/javascript", "text/javascript", "text/x-python", "application/x-python-code", "text/x-perl",
        "application/x-perl", "text/x-ruby", "application/x-httpd-php", "text/html", "application/xhtml+xml",
        "image/svg+xml", "application/vnd.android.package-archive", "application/x-apple-diskimage",
    )
}
