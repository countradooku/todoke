// Finished transfers, searchable, kept as long as the settings say (§7.7:
// local policy), and clearable.

package org.todoke.android.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import org.todoke.android.R

@Composable
fun HistoryScreen(state: UiState, modifier: Modifier, onLoad: () -> Unit, onClear: () -> Unit) {
    LaunchedEffect(Unit) { onLoad() }
    var query by rememberSaveable { mutableStateOf("") }
    val shown = state.history.filter { item ->
        query.isBlank() || item.names.any { it.contains(query, ignoreCase = true) } ||
            item.manifestHash.startsWith(query, ignoreCase = true)
    }
    Column(modifier.fillMaxSize().padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(stringResource(R.string.nav_history), style = MaterialTheme.typography.titleLarge, modifier = Modifier.weight(1f))
            TextButton(onClick = onClear, enabled = state.history.isNotEmpty()) { Text(stringResource(R.string.clear)) }
        }
        OutlinedTextField(
            value = query,
            onValueChange = { query = it },
            label = { Text(stringResource(R.string.search)) },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            items(shown, key = { it.transfer }) { item ->
                Column(Modifier.fillMaxWidth()) {
                    Text(item.names.joinToString(", ").ifEmpty { "—" }, style = MaterialTheme.typography.titleSmall)
                    Text(
                        "${stateLabel(item.state)} · ${Format.bytes(item.bytes.toLong())} · ${item.manifestHash.take(16)}",
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
            }
        }
    }
}
