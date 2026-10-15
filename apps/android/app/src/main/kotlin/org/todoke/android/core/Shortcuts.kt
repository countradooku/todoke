// Direct Share: the contacts appear as targets in the system share sheet
// (sharing shortcuts with the category in res/xml/shortcuts.xml). Names
// only, never a fingerprint; at most four, the ones reachable now first.

package org.todoke.android.core

import android.content.Context
import android.content.Intent
import androidx.core.content.pm.ShortcutInfoCompat
import androidx.core.content.pm.ShortcutManagerCompat
import androidx.core.graphics.drawable.IconCompat
import org.todoke.android.MainActivity
import org.todoke.android.R
import org.todoke.ffi.Contact

object Shortcuts {
    private const val CATEGORY = "org.todoke.android.SHARE_TARGET"
    private const val MAX = 4

    fun publish(context: Context, contacts: List<Contact>) {
        val shown = contacts.sortedByDescending { it.available }.take(MAX)
        val shortcuts = shown.map { contact ->
            ShortcutInfoCompat.Builder(context, contact.device)
                .setShortLabel(contact.name)
                .setIcon(IconCompat.createWithResource(context, R.drawable.ic_contact))
                .setIntent(Intent(context, MainActivity::class.java).setAction(Intent.ACTION_VIEW))
                .setCategories(setOf(CATEGORY))
                .setLongLived(true)
                .build()
        }
        ShortcutManagerCompat.removeAllDynamicShortcuts(context)
        shortcuts.forEach { ShortcutManagerCompat.pushDynamicShortcut(context, it) }
    }
}
