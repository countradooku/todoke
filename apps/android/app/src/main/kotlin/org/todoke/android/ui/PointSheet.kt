// Point to share (PROTOCOL §10.4): while the sheet shows, this device ranges
// with the nearby contacts that can be pointed at, and lists them by how
// straight ahead each is; the one pointed at comes first and is marked.
// Choosing one opens the file picker for it, as its Send button does: the
// ranging only suggests, the user still picks.

package org.todoke.android.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import kotlin.math.abs
import kotlin.math.roundToInt
import org.todoke.android.R
import org.todoke.android.radio.Bearing
import org.todoke.android.radio.Pointing
import org.todoke.ffi.Contact

/** How far off straight ahead (degrees) still counts as pointed at. */
private const val AHEAD_DEGREES = 20f

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PointSheet(pointing: Pointing, contacts: List<Contact>, onChoose: (String) -> Unit, onDismiss: () -> Unit) {
    val bearings by pointing.bearings.collectAsStateWithLifecycle()
    val nearby = contacts.count { it.nearby || it.connected }
    LaunchedEffect(Unit) { runCatching { pointing.start(nearby) } }
    DisposableEffect(Unit) { onDispose { pointing.close() } }
    val ranked = bearings.values.sortedBy { abs(it.azimuth ?: 180f) }
    ModalBottomSheet(onDismissRequest = onDismiss) {
        Column(Modifier.fillMaxWidth().padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text(stringResource(R.string.pointing), style = MaterialTheme.typography.titleLarge)
            Text(stringResource(if (ranked.isEmpty()) R.string.pointing_searching else R.string.pointing_hint))
            ranked.forEachIndexed { index, bearing ->
                val contact = contacts.firstOrNull { it.device == bearing.contact } ?: return@forEachIndexed
                val ahead = index == 0 && abs(bearing.azimuth ?: 180f) <= AHEAD_DEGREES
                Target(contact.name, bearing, ahead) { onChoose(contact.device) }
            }
            OutlinedButton(onClick = onDismiss) { Text(stringResource(R.string.done)) }
        }
    }
}

@Composable
private fun Target(name: String, bearing: Bearing, ahead: Boolean, onChoose: () -> Unit) {
    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f)) {
            Text(name, style = if (ahead) MaterialTheme.typography.titleLarge else MaterialTheme.typography.titleMedium)
            val where = listOfNotNull(
                bearing.meters?.let { stringResource(R.string.pointing_meters, (it * 10).roundToInt() / 10f) },
                if (ahead) stringResource(R.string.pointing_ahead) else null,
            ).joinToString(" · ")
            if (where.isNotEmpty()) Text(where, style = MaterialTheme.typography.bodySmall)
        }
        Button(onClick = onChoose) { Text(stringResource(R.string.send)) }
    }
}
