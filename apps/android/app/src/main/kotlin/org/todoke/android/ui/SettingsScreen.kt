// Settings: who can see this device (contacts, everyone for five minutes
// through a pairing code, or hidden), where received files go, nearby
// radios (direct Wi-Fi links, pointing), how the storage key is protected,
// and about.

package org.todoke.android.ui

import android.content.Intent
import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.dp
import org.todoke.android.BuildConfig
import org.todoke.android.R
import org.todoke.android.TodokeApplication
import org.todoke.ffi.KeyProtection

@Composable
fun SettingsScreen(state: UiState, modifier: Modifier, onHidden: (Boolean) -> Unit, onPair: () -> Unit) {
    val context = LocalContext.current
    val app = context.applicationContext as TodokeApplication
    var exportTree by remember { mutableStateOf(app.prefs.exportTree) }
    val folder = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocumentTree()) { uri ->
        if (uri != null) {
            val access = Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION
            context.contentResolver.takePersistableUriPermission(uri, access)
            // The folder chosen before is no longer needed: give its grant up.
            app.prefs.exportTree?.let(Uri::parse)?.takeIf { it != uri }?.let { old ->
                runCatching { context.contentResolver.releasePersistableUriPermission(old, access) }
            }
            app.prefs.exportTree = uri.toString()
            exportTree = uri.toString()
            app.exportReceived()
        }
    }
    val hidden = state.status?.hidden ?: app.prefs.hidden
    Column(
        modifier.fillMaxSize().padding(16.dp).verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(stringResource(R.string.nav_settings), style = MaterialTheme.typography.titleLarge)
        Text(stringResource(R.string.visibility), style = MaterialTheme.typography.titleMedium)
        Column(Modifier.selectableGroup()) {
            Choice(stringResource(R.string.visibility_contacts), selected = !hidden) {
                app.prefs.hidden = false
                onHidden(false)
            }
            Choice(stringResource(R.string.visibility_everyone), selected = false) { onPair() }
            Choice(stringResource(R.string.visibility_hidden), selected = hidden) {
                app.prefs.hidden = true
                onHidden(true)
            }
        }
        HorizontalDivider()
        Text(stringResource(R.string.receiving), style = MaterialTheme.typography.titleMedium)
        Text(exportTree?.let { stringResource(R.string.export_folder_set) } ?: stringResource(R.string.export_folder_none))
        OutlinedButton(onClick = { folder.launch(null) }) { Text(stringResource(R.string.choose_folder)) }
        HorizontalDivider()
        NearbySettings()
        HorizontalDivider()
        Text(stringResource(R.string.security), style = MaterialTheme.typography.titleMedium)
        val protection = when (state.status?.keyProtection) {
            KeyProtection.STRONG_BOX -> stringResource(R.string.key_strongbox)
            KeyProtection.TEE -> stringResource(R.string.key_tee)
            null -> "—"
            else -> stringResource(R.string.key_other)
        }
        Text(protection)
        Text(stringResource(if (app.prefs.gate) R.string.unlock_required else R.string.unlock_not_required))
        HorizontalDivider()
        Text(stringResource(R.string.about), style = MaterialTheme.typography.titleMedium)
        Text("todoke ${BuildConfig.VERSION_NAME}")
        state.status?.let { Text(stringResource(R.string.this_device, Format.fingerprint(it.device))) }
    }
}

@Composable
private fun Choice(label: String, selected: Boolean, onSelect: () -> Unit) {
    Row(
        Modifier.fillMaxWidth().heightIn(min = 48.dp)
            .selectable(selected = selected, onClick = onSelect, role = Role.RadioButton).padding(8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        RadioButton(selected = selected, onClick = null)
        Text(label, modifier = Modifier.padding(start = 8.dp))
    }
}
