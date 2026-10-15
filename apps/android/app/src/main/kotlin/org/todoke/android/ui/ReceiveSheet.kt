// The receive sheet: an offer waits for the user's decision (PROTOCOL §7.2:
// nothing is accepted before it). The sender's seal claims only what the
// session proved: a verified contact. Names are escaped by the core and
// their extension is drawn apart, programs are flagged, and the buttons stay
// disabled for 700 ms each time the offer shown changes, so a tap aimed at
// what was there before cannot accept it. A resumed transfer can only repeat
// its earlier selection (§7.5).

@file:OptIn(ExperimentalUnsignedTypes::class)

package org.todoke.android.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.foundation.selection.toggleable
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.delay
import org.todoke.android.R
import org.todoke.ffi.Entry
import org.todoke.ffi.Offer

/** How long the decision buttons stay disabled after an offer appears. */
const val ARM_DELAY_MS = 700L

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ReceiveSheet(offer: Offer, onAccept: (List<UInt>) -> Unit, onDecline: () -> Unit) {
    var hidden by remember(offer.transfer) { mutableStateOf(false) }
    if (hidden) return
    var armed by remember(offer.transfer) { mutableStateOf(false) }
    var choosing by remember(offer.transfer) { mutableStateOf(false) }
    val chosen = remember(offer.transfer) { mutableStateListOf<UInt>() }
    LaunchedEffect(offer.transfer) {
        armed = false
        delay(ARM_DELAY_MS)
        armed = true
    }
    val files = offer.entries.filter { !it.directory }
    val folders = offer.entries.count { it.directory }
    val programs = files.any(Format::isProgram)
    val resumed = offer.resume.isNotEmpty()
    // Escape hides the sheet; the offer waits until it expires (§13). It
    // opens whole, so the decision is never below the fold.
    ModalBottomSheet(
        onDismissRequest = { hidden = true },
        sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true),
    ) {
        Column(Modifier.navigationBarsPadding().padding(horizontal = 24.dp, vertical = 8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(stringResource(R.string.offer_from, offer.fromName), style = MaterialTheme.typography.titleLarge)
            Text(stringResource(R.string.verified_contact), color = MaterialTheme.colorScheme.primary)
            Text(
                pluralStringResource(R.plurals.offer_counts, files.size, files.size) +
                    (if (folders > 0) " · " + pluralStringResource(R.plurals.folders, folders, folders) else "") +
                    " · " + Format.bytes(offer.totalBytes.toLong()),
            )
            if (programs) {
                Text(
                    stringResource(R.string.programs_warning),
                    color = MaterialTheme.colorScheme.error,
                    modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite },
                )
            }
            if (resumed) Text(stringResource(R.string.resumed_offer))
            LazyColumn(Modifier.heightIn(max = 320.dp)) {
                items(files, key = { it.id.toLong() }) { entry ->
                    EntryRow(entry, choosing, entry.id in chosen) { picked ->
                        if (picked) chosen += entry.id else chosen -= entry.id
                    }
                }
            }
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp, Alignment.End)) {
                TextButton(onClick = onDecline, enabled = armed) { Text(stringResource(R.string.decline)) }
                if (choosing) {
                    Button(onClick = { onAccept(chosen.toList()) }, enabled = armed && chosen.isNotEmpty()) {
                        Text(stringResource(R.string.accept_chosen))
                    }
                } else {
                    if (!resumed) {
                        OutlinedButton(onClick = { choosing = true }, enabled = armed) { Text(stringResource(R.string.choose)) }
                    }
                    Button(onClick = { onAccept(if (resumed) offer.resume.toList() else emptyList()) }, enabled = armed) {
                        Text(stringResource(R.string.accept_all))
                    }
                }
            }
        }
    }
}

@Composable
private fun EntryRow(entry: Entry, choosing: Boolean, picked: Boolean, onPick: (Boolean) -> Unit) {
    val (stem, extension) = Format.nameParts(entry.name)
    // One control per file while choosing: tapping the name toggles it.
    val row = Modifier.fillMaxWidth().heightIn(min = 48.dp).padding(vertical = 4.dp)
    Row(
        if (choosing) row.toggleable(value = picked, onValueChange = onPick, role = Role.Checkbox) else row,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        if (choosing) Checkbox(checked = picked, onCheckedChange = null)
        Text(stem, maxLines = 1, modifier = Modifier.weight(1f, fill = false))
        Text(extension, color = if (Format.isProgram(entry)) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurface)
        Text("  " + Format.bytes(entry.size.toLong()), style = MaterialTheme.typography.bodySmall)
    }
}
