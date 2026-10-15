// Direct Share shortcuts: the system sees a name and an opaque ID, never a
// fingerprint, and a share through a shortcut finds its contact again.

package org.todoke.android

import androidx.core.content.pm.ShortcutManagerCompat
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.filters.SdkSuppress
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Test
import org.junit.runner.RunWith
import org.todoke.android.core.Shortcuts

// Sharing shortcuts need the shortcut service (Android 7.1).
@SdkSuppress(minSdkVersion = 25)
@RunWith(AndroidJUnit4::class)
class ShortcutsTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val contacts = listOf(
        FakeBackend.contact("a1", "Pixel 9", available = true),
        FakeBackend.contact("b2", "MacBook", available = false),
    )

    @After
    fun cleanUp() = ShortcutManagerCompat.removeAllDynamicShortcuts(context)

    @Test
    fun shortcutsCarryNamesAndOpaqueIds() {
        Shortcuts.publish(context, contacts)
        val published = ShortcutManagerCompat.getDynamicShortcuts(context)
        assertEquals(setOf("Pixel 9", "MacBook"), published.map { it.shortLabel.toString() }.toSet())
        for (shortcut in published) {
            assertEquals(32, shortcut.id.length)
            assertFalse(contacts.any { shortcut.id.contains(it.device.take(16)) })
            val contact = Shortcuts.contact(context, shortcut.id, contacts)
            assertEquals(shortcut.shortLabel.toString(), contacts.first { it.device == contact }.name)
        }
    }

    @Test
    fun anUnknownShortcutFindsNobody() {
        assertNull(Shortcuts.contact(context, "a1".repeat(32), contacts))
        assertNull(Shortcuts.contact(context, "0".repeat(32), contacts))
    }

    /** A contact no longer shown leaves the share sheet, cached or not. */
    @Test
    fun removedContactsLeaveTheShareSheet() {
        Shortcuts.publish(context, contacts)
        Shortcuts.publish(context, contacts.take(1))
        val left = ShortcutManagerCompat.getShortcuts(
            context,
            ShortcutManagerCompat.FLAG_MATCH_DYNAMIC or ShortcutManagerCompat.FLAG_MATCH_CACHED,
        )
        assertEquals(listOf("Pixel 9"), left.map { it.shortLabel.toString() })
    }
}
