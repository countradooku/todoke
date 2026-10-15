// Transfers in both directions, with progress and a way to cancel.

package org.todoke.android.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Card
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import org.todoke.android.R
import org.todoke.ffi.TransferState
import org.todoke.ffi.Way

@Composable
fun TransfersScreen(state: UiState, modifier: Modifier, onCancel: (String) -> Unit) {
    Column(modifier.fillMaxSize().padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(stringResource(R.string.nav_transfers), style = MaterialTheme.typography.titleLarge)
        if (state.transfers.isEmpty()) Text(stringResource(R.string.no_transfers))
        LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            items(state.transfers, key = { it.id }) { transfer ->
                val peer = state.contacts.firstOrNull { it.device == transfer.peer }?.name ?: Format.fingerprint(transfer.peer)
                val fraction = if (transfer.bytesTotal > 0u) {
                    (transfer.bytesDone.toDouble() / transfer.bytesTotal.toDouble()).toFloat()
                } else {
                    0f
                }
                Card(Modifier.fillMaxWidth()) {
                    Column(Modifier.padding(16.dp)) {
                        // Cancel's touch area is 48 dp: the row keeps it, and the
                        // gap keeps the progress bar's taller semantics off it.
                        Row(Modifier.fillMaxWidth().heightIn(min = 48.dp), verticalAlignment = Alignment.CenterVertically) {
                            Text(
                                stringResource(if (transfer.way == Way.INCOMING) R.string.from_peer else R.string.to_peer, peer),
                                modifier = Modifier.weight(1f),
                            )
                            if (transfer.state in CANCELLABLE) {
                                TextButton(onClick = { onCancel(transfer.id) }) {
                                    Text(stringResource(R.string.cancel))
                                }
                            }
                        }
                        LinearProgressIndicator(progress = { fraction }, modifier = Modifier.padding(top = 12.dp).fillMaxWidth())
                        Text(
                            "${Format.bytes(transfer.bytesDone.toLong())} / ${Format.bytes(transfer.bytesTotal.toLong())} · ${stateLabel(transfer.state)}",
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                }
            }
        }
    }
}

private val CANCELLABLE = setOf(
    TransferState.OFFERED,
    TransferState.AWAITING_DECISION,
    TransferState.ACCEPTED,
    TransferState.TRANSFERRING,
    TransferState.INTERRUPTED,
)

@Composable
fun stateLabel(state: TransferState): String = stringResource(
    when (state) {
        TransferState.OFFERED -> R.string.state_offered
        TransferState.AWAITING_DECISION -> R.string.state_waiting
        TransferState.ACCEPTED, TransferState.TRANSFERRING -> R.string.state_transferring
        TransferState.INTERRUPTED -> R.string.state_interrupted
        TransferState.RECEIVED -> R.string.state_received
        TransferState.DELIVERED -> R.string.state_delivered
        TransferState.UNCONFIRMED -> R.string.state_unconfirmed
        TransferState.REJECTED -> R.string.state_declined
        TransferState.CANCELLED -> R.string.state_cancelled
        TransferState.FAILED -> R.string.state_failed
    },
)
