// Files shared from another app: which contact gets them (preselected when
// a Direct Share shortcut was used).

package org.todoke.android.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import org.todoke.android.R
import org.todoke.ffi.Contact

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ShareSheet(contacts: List<Contact>, count: Int, preselected: String?, onSend: (String) -> Unit, onDismiss: () -> Unit) {
    ModalBottomSheet(onDismissRequest = onDismiss, sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)) {
        Column(Modifier.navigationBarsPadding().padding(horizontal = 24.dp, vertical = 8.dp)) {
            Text(pluralStringResource(R.plurals.share_count, count, count), style = MaterialTheme.typography.titleLarge)
            if (contacts.isEmpty()) Text(stringResource(R.string.no_devices))
            LazyColumn {
                items(contacts.sortedByDescending { it.device == preselected }, key = { it.device }) { contact ->
                    TextButton(onClick = { onSend(contact.device) }, enabled = contact.available) {
                        Text(contact.name + if (contact.device == preselected) " ✓" else "")
                    }
                }
            }
        }
    }
}
