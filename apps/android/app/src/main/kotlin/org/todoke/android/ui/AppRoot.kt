// The app's frame: four destinations (Home, Transfers, History, Settings),
// pairing as a full screen, and the receive sheet over everything whenever
// an offer waits for the user's decision.

package org.todoke.android.ui

import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.automirrored.filled.List
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import org.todoke.android.R

enum class Destination(val label: Int, val icon: ImageVector) {
    Home(R.string.nav_home, Icons.Filled.Home),
    Transfers(R.string.nav_transfers, Icons.Filled.Refresh),
    History(R.string.nav_history, Icons.AutoMirrored.Filled.List),
    Settings(R.string.nav_settings, Icons.Filled.Settings),
}

@Composable
fun AppRoot(
    model: AppViewModel,
    onTransferStarted: () -> Unit,
    start: Destination = Destination.Home,
    startPairing: Int? = null,
) {
    val state by model.state.collectAsStateWithLifecycle()
    var destination by rememberSaveable { mutableStateOf(start) }
    var pairing by rememberSaveable { mutableStateOf(startPairing != null) }
    val snackbar = remember { SnackbarHostState() }
    LaunchedEffect(state.notice) {
        state.notice?.let {
            snackbar.showSnackbar(it)
            model.dismissNotice()
        }
    }
    if (pairing) {
        PairScreen(model.backend, onDone = { pairing = false }, startTab = startPairing ?: 0)
        return
    }
    Scaffold(
        snackbarHost = { SnackbarHost(snackbar) },
        bottomBar = {
            NavigationBar {
                Destination.entries.forEach { item ->
                    NavigationBarItem(
                        selected = item == destination,
                        onClick = { destination = item },
                        icon = { Icon(item.icon, contentDescription = null) },
                        label = { Text(stringResource(item.label)) },
                    )
                }
            }
        },
    ) { padding ->
        val modifier = Modifier.padding(padding)
        when (destination) {
            Destination.Home -> HomeScreen(
                state,
                modifier,
                onPair = { pairing = true },
                onSend = { contact, documents ->
                    model.send(contact, documents)
                    onTransferStarted()
                },
            )
            Destination.Transfers -> TransfersScreen(state, modifier, onCancel = model::cancel)
            Destination.History -> HistoryScreen(state, modifier, onLoad = { model.loadHistory() }, onClear = model::clearHistory)
            Destination.Settings -> SettingsScreen(state, modifier, onHidden = model::setHidden, onPair = { pairing = true })
        }
    }
    state.offers.firstOrNull()?.let { offer ->
        ReceiveSheet(
            offer = offer,
            onAccept = { files ->
                model.accept(offer.transfer, files)
                onTransferStarted()
            },
            onDecline = { model.decline(offer.transfer) },
        )
    }
}
