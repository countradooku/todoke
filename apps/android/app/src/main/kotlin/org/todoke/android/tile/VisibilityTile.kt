// A Quick Settings tile: visible to contacts, or hidden.

package org.todoke.android.tile

import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import org.todoke.android.R
import org.todoke.android.TodokeApplication

class VisibilityTile : TileService() {
    private val app get() = application as TodokeApplication

    override fun onStartListening() = show()

    override fun onClick() {
        val hidden = !app.prefs.hidden
        app.prefs.hidden = hidden
        app.backendOrNull()?.let { backend ->
            CoroutineScope(Dispatchers.IO).launch { runCatching { backend.setHidden(hidden) } }
        }
        show()
    }

    private fun show() {
        val tile = qsTile ?: return
        val hidden = app.prefs.hidden
        tile.state = if (hidden) Tile.STATE_INACTIVE else Tile.STATE_ACTIVE
        tile.label = getString(R.string.app_name)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            tile.subtitle = getString(if (hidden) R.string.visibility_hidden else R.string.visibility_contacts)
        }
        tile.updateTile()
    }
}
