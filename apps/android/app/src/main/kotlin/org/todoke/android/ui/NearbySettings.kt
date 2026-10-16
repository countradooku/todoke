// Settings for nearby radios: direct Wi-Fi links and pointing, each with
// its permission explained once before the system asks, and what works
// without it. Denied, the feature stays off and transfers go over the
// network and the relay as before.

package org.todoke.android.ui

import android.content.Intent
import android.net.Uri
import android.provider.Settings
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import org.todoke.android.R
import org.todoke.android.TodokeApplication
import org.todoke.android.radio.NearbyPermissions

@Composable
fun NearbySettings() {
    val context = LocalContext.current
    val app = context.applicationContext as TodokeApplication
    Text(stringResource(R.string.nearby), style = MaterialTheme.typography.titleMedium)
    Permission(
        key = "wifi",
        title = stringResource(R.string.direct_links),
        why = stringResource(R.string.direct_links_why),
        off = stringResource(R.string.direct_links_off),
        permissions = NearbyPermissions.wifi,
        granted = { NearbyPermissions.wifiGranted(context) },
    )
    val pointing = app.pointing
    if (pointing != null && android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.S &&
        context.packageManager.hasSystemFeature(android.content.pm.PackageManager.FEATURE_UWB)
    ) {
        val scope = rememberCoroutineScope()
        Permission(
            key = "uwb",
            title = stringResource(R.string.pointing),
            why = stringResource(R.string.pointing_why),
            off = stringResource(R.string.pointing_off),
            permissions = arrayOf(NearbyPermissions.UWB),
            granted = { NearbyPermissions.uwbGranted(context) },
            onGranted = { scope.launch { pointing.refresh() } },
        )
    }
}

/** One permission: what it is for, asked after a one-time explanation. */
@Composable
private fun Permission(
    key: String,
    title: String,
    why: String,
    off: String,
    permissions: Array<String>,
    granted: () -> Boolean,
    onGranted: () -> Unit = {},
) {
    val context = LocalContext.current
    val app = context.applicationContext as TodokeApplication
    val state = remember { MutableStateFlow(granted()) }
    val allowed by state.collectAsStateWithLifecycle()
    var explaining by remember { mutableStateOf(false) }
    var refused by remember { mutableStateOf(false) }
    val request = rememberLauncherForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) {
        state.value = granted()
        refused = !state.value
        if (state.value) onGranted()
    }
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text(title, style = MaterialTheme.typography.titleSmall)
        Text(if (allowed) stringResource(R.string.allowed) else off, style = MaterialTheme.typography.bodySmall)
        when {
            allowed -> {}
            // Asked and refused: only the system settings can change it now.
            refused -> OutlinedButton(onClick = {
                context.startActivity(
                    Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.fromParts("package", context.packageName, null)),
                )
            }) { Text(stringResource(R.string.open_settings)) }
            else -> OutlinedButton(onClick = {
                if (app.prefs.explained(key)) request.launch(permissions) else explaining = true
            }) { Text(stringResource(R.string.allow)) }
        }
    }
    if (explaining) {
        AlertDialog(
            onDismissRequest = { explaining = false },
            title = { Text(title) },
            text = { Text(why) },
            confirmButton = {
                TextButton(onClick = {
                    explaining = false
                    app.prefs.setExplained(key)
                    request.launch(permissions)
                }) { Text(stringResource(R.string.continue_label)) }
            },
            dismissButton = { TextButton(onClick = { explaining = false }) { Text(stringResource(R.string.not_now)) } },
        )
    }
}
