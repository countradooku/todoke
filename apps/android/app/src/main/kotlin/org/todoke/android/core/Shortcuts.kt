// Direct Share: the contacts appear as targets in the system share sheet
// (sharing shortcuts with the category in res/xml/shortcuts.xml). The
// system keeps each shortcut's label and ID: the label is the contact's
// name, the ID a keyed hash of its fingerprint (never the fingerprint).
// At most four, the ones reachable now first.

package org.todoke.android.core

import android.content.Context
import android.content.Intent
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import androidx.core.content.pm.ShortcutInfoCompat
import androidx.core.content.pm.ShortcutManagerCompat
import androidx.core.graphics.drawable.IconCompat
import org.todoke.android.MainActivity
import org.todoke.android.TodokeApplication
import org.todoke.android.R
import org.todoke.ffi.Contact

object Shortcuts {
    private const val CATEGORY = "org.todoke.android.SHARE_TARGET"
    private const val MAX = 4

    fun publish(context: Context, contacts: List<Contact>) {
        val shown = contacts.sortedByDescending { it.available }.take(MAX)
        val shortcuts = shown.map { contact ->
            ShortcutInfoCompat.Builder(context, id(context, contact.device))
                .setShortLabel(contact.name)
                .setIcon(IconCompat.createWithResource(context, R.drawable.ic_contact))
                .setIntent(Intent(context, MainActivity::class.java).setAction(Intent.ACTION_VIEW))
                .setCategories(setOf(CATEGORY))
                .setLongLived(true)
                .build()
        }
        // Long-lived shortcuts stay cached by the system after they stop
        // being dynamic: remove those of contacts no longer shown, so a
        // removed contact leaves the share sheet.
        val kept = shortcuts.map { it.id }.toSet()
        val stale = ShortcutManagerCompat.getShortcuts(
            context,
            ShortcutManagerCompat.FLAG_MATCH_DYNAMIC or ShortcutManagerCompat.FLAG_MATCH_CACHED,
        ).map { it.id }.filter { it !in kept }
        if (stale.isNotEmpty()) ShortcutManagerCompat.removeLongLivedShortcuts(context, stale)
        ShortcutManagerCompat.removeAllDynamicShortcuts(context)
        shortcuts.forEach { ShortcutManagerCompat.pushDynamicShortcut(context, it) }
    }

    /** The contact a share through shortcut `id` is for, if still one. */
    fun contact(context: Context, id: String, contacts: List<Contact>): String? =
        contacts.firstOrNull { id(context, it.device) == id }?.device

    /** HMAC-SHA-256 of the fingerprint under this install's random key,
     * 128 bits in hex. */
    private fun id(context: Context, device: String): String {
        val key = (context.applicationContext as TodokeApplication).prefs.shortcutKey()
        val mac = Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(key, "HmacSHA256")) }
        return mac.doFinal(device.toByteArray()).take(16).joinToString("") { "%02x".format(it) }
    }
}
