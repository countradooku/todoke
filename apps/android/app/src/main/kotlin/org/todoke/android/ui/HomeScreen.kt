// Home: the paired devices (with whether each is nearby and how it is
// reached) and the way to send them files, plus pairing a new device.

package org.todoke.android.ui

import android.net.Uri
import android.provider.OpenableColumns
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import org.todoke.android.R
import org.todoke.android.core.Picked
import org.todoke.ffi.Contact
import org.todoke.ffi.Route

@Composable
fun HomeScreen(state: UiState, modifier: Modifier, onPair: () -> Unit, onSend: (String, List<Picked>) -> Unit) {
    val context = LocalContext.current
    var target by rememberSaveable { mutableStateOf<String?>(null) }
    val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenMultipleDocuments()) { uris ->
        val contact = target ?: return@rememberLauncherForActivityResult
        target = null
        if (uris.isNotEmpty()) onSend(contact, uris.map { Picked(it, displayName(context, it)) })
    }
    Column(modifier.fillMaxSize().padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        if (state.status?.sessionsEnabled == false) {
            Text(stringResource(R.string.sessions_disabled), color = MaterialTheme.colorScheme.error)
        }
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            Text(stringResource(R.string.devices), style = MaterialTheme.typography.titleLarge, modifier = Modifier.weight(1f))
            FilledTonalButton(onClick = onPair) { Text(stringResource(R.string.pair_device)) }
        }
        if (state.contacts.isEmpty()) {
            Text(stringResource(R.string.no_devices), style = MaterialTheme.typography.bodyLarge)
        }
        LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            items(state.contacts, key = { it.device }) { contact ->
                ContactCard(contact, onSend = {
                    target = contact.device
                    picker.launch(arrayOf("*/*"))
                })
            }
        }
    }
}

@Composable
private fun ContactCard(contact: Contact, onSend: () -> Unit) {
    val where = when {
        contact.connected && contact.route == Route.RELAY -> stringResource(R.string.route_relay)
        contact.connected || contact.nearby -> stringResource(R.string.route_nearby)
        else -> stringResource(R.string.route_away)
    }
    Card(Modifier.fillMaxWidth()) {
        Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text(contact.name, style = MaterialTheme.typography.titleMedium)
                Text(
                    Format.fingerprint(contact.device),
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.semantics { contentDescription = "" },
                )
                AssistChip(onClick = {}, label = { Text(where) }, enabled = false)
            }
            Button(onClick = onSend, enabled = contact.available) { Text(stringResource(R.string.send)) }
        }
    }
}

/** The name the provider shows for a picked document (never a path). */
fun displayName(context: android.content.Context, uri: Uri): String =
    context.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { cursor ->
        if (cursor.moveToFirst()) cursor.getString(0) else null
    } ?: uri.lastPathSegment?.substringAfterLast('/') ?: "file"
