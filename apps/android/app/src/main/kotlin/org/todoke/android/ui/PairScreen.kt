// Pairing (PROTOCOL §3): show a QR code (drawn from the core's modules; its
// text never reaches the app), scan another device's, or pair with a code.
// While the QR code shows, an NFC reader can take the same offer by tapping
// (§3.1.1); the scan tab reads such taps too.
// While a secret is on screen the window is FLAG_SECURE: no screenshot, no
// thumbnail in recent apps. Leaving stops the pairing offer.

package org.todoke.android.ui

import android.app.Activity
import android.view.WindowManager
import androidx.activity.compose.BackHandler
import androidx.activity.compose.LocalActivity
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.PrimaryTabRow
import androidx.compose.material3.Tab
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import org.todoke.android.R
import org.todoke.android.core.Backend
import org.todoke.android.core.PairingCode
import org.todoke.android.core.QrCode
import org.todoke.android.radio.NfcPairing
import org.todoke.ffi.Stranger

@Composable
fun PairScreen(backend: Backend, onDone: () -> Unit, startTab: Int = 0) {
    var tab by rememberSaveable { mutableStateOf(startTab) }
    val scope = rememberCoroutineScope()
    SecureWindow()
    DisposableEffect(Unit) {
        // Leaving cancels this scope: the stop must run anyway.
        onDispose { scope.launch(NonCancellable) { runCatching { backend.stopPairing() } } }
    }
    BackHandler(onBack = onDone)
    Column(Modifier.fillMaxSize().safeDrawingPadding().padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text(stringResource(R.string.pair_device), style = MaterialTheme.typography.titleLarge)
        PrimaryTabRow(selectedTabIndex = tab) {
            listOf(R.string.pair_show_qr, R.string.pair_scan, R.string.pair_code).forEachIndexed { index, label ->
                Tab(selected = tab == index, onClick = { tab = index }, text = { Text(stringResource(label)) })
            }
        }
        when (tab) {
            0 -> ShowQr(backend)
            1 -> ScanQr(backend, onDone)
            else -> Codes(backend, onDone)
        }
        TextButton(onClick = onDone) { Text(stringResource(R.string.done)) }
    }
}

/** Marks the window secure while shown. */
@Composable
private fun SecureWindow() {
    val activity = LocalActivity.current ?: return
    DisposableEffect(activity) {
        activity.window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        onDispose { activity.window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE) }
    }
}

@Composable
private fun ShowQr(backend: Backend) {
    var qr by remember { mutableStateOf<QrCode?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    val activity = LocalActivity.current
    LaunchedEffect(Unit) {
        runCatching { backend.showQr() }.onSuccess { qr = it }.onFailure { error = it.message }
    }
    // The same offer by NFC, only while it is on screen: from resume to
    // pause, and never once it expires; the tag is closed with the screen.
    val tag = qr?.nfc
    val lifecycle = LocalLifecycleOwner.current.lifecycle
    var expired by remember(qr) { mutableStateOf(false) }
    LaunchedEffect(qr) {
        val code = qr ?: return@LaunchedEffect
        delay((code.expiresAt * 1_000 - System.currentTimeMillis()).coerceAtLeast(0))
        expired = true
    }
    if (activity != null && tag != null) {
        DisposableEffect(tag, expired) {
            val observer = LifecycleEventObserver { _, event ->
                when (event) {
                    Lifecycle.Event.ON_RESUME -> if (!expired) NfcPairing.serve(activity, tag)
                    Lifecycle.Event.ON_PAUSE -> NfcPairing.withdraw(activity, tag)
                    else -> {}
                }
            }
            // Adding it replays the events up to the current state.
            lifecycle.addObserver(observer)
            if (expired) NfcPairing.withdraw(activity, tag)
            onDispose {
                lifecycle.removeObserver(observer)
                NfcPairing.withdraw(activity, tag)
            }
        }
        DisposableEffect(tag) { onDispose { tag.close() } }
    }
    Text(stringResource(R.string.pair_show_qr_hint))
    if (tag != null && activity != null && NfcPairing.enabled(activity)) {
        Text(stringResource(R.string.pair_tap_hint), style = MaterialTheme.typography.bodySmall)
    }
    error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
    qr?.let { QrView(it) }
}

/** The QR code, black on white whatever the theme, with a quiet zone. Its
 * label says it is secret and never reads it out. */
/** Light modules around a QR code, on each side (ISO/IEC 18004). */
private const val QUIET_ZONE = 4

@Composable
fun QrView(qr: QrCode) {
    val label = stringResource(R.string.qr_secret_label)
    Canvas(
        Modifier.fillMaxWidth().aspectRatio(1f).background(Color.White)
            .semantics { contentDescription = label },
    ) {
        // The quiet zone the QR standard asks for: 4 light modules a side.
        val cell = size.minDimension / (qr.width + 2 * QUIET_ZONE)
        for (y in 0 until qr.width) {
            for (x in 0 until qr.width) {
                if (qr.dark(x, y)) {
                    drawRect(Color.Black, topLeft = Offset((x + QUIET_ZONE) * cell, (y + QUIET_ZONE) * cell), size = Size(cell, cell))
                }
            }
        }
    }
}

@Composable
private fun ScanQr(backend: Backend, onDone: () -> Unit) {
    val scope = rememberCoroutineScope()
    var error by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    val activity = LocalActivity.current
    fun pair(attempt: suspend () -> String) {
        if (busy) return
        busy = true
        scope.launch {
            runCatching { attempt() }
                .onSuccess { onDone() }
                .onFailure {
                    error = it.message
                    busy = false
                }
        }
    }
    // Taps on a device showing its QR code (NFC reader mode, this screen only).
    if (activity != null) {
        DisposableEffect(activity) {
            val stop = NfcPairing.read(activity) { message ->
                activity.runOnUiThread { pair { backend.scanNfc(message) } }
            }
            onDispose { stop() }
        }
    }
    Text(stringResource(R.string.pair_scan_hint))
    if (activity != null && NfcPairing.enabled(activity)) {
        Text(stringResource(R.string.pair_tap_scan_hint), style = MaterialTheme.typography.bodySmall)
    }
    error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
    if (!busy) {
        QrScanner(onScanned = { text -> pair { backend.scanQr(text) } })
    }
}

@Composable
private fun Codes(backend: Backend, onDone: () -> Unit) {
    val scope = rememberCoroutineScope()
    var shown by remember { mutableStateOf<PairingCode?>(null) }
    var strangers by remember { mutableStateOf<List<Stranger>>(emptyList()) }
    var picked by remember { mutableStateOf<String?>(null) }
    var code by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    LaunchedEffect(Unit) {
        while (true) {
            runCatching { backend.strangers() }.onSuccess { strangers = it }
            delay(2_000)
        }
    }
    Text(stringResource(R.string.pair_code_hint))
    Button(onClick = { scope.launch { runCatching { backend.showCode() }.onSuccess { shown = it }.onFailure { error = it.message } } }) {
        Text(stringResource(R.string.show_code))
    }
    shown?.let {
        Text(it.code.chunked(5).joinToString(" "), style = MaterialTheme.typography.displaySmall)
    }
    Text(stringResource(R.string.nearby_devices), style = MaterialTheme.typography.titleMedium)
    LazyColumn {
        items(strangers, key = { it.stranger }) { stranger ->
            TextButton(onClick = { picked = stranger.stranger }) {
                Text(stringResource(R.string.nearby_device, stranger.stranger.take(8)))
            }
        }
    }
    picked?.let { stranger ->
        OutlinedTextField(
            value = code,
            onValueChange = { value -> code = value.filter(Char::isDigit).take(10) },
            label = { Text(stringResource(R.string.enter_code)) },
            visualTransformation = PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
            singleLine = true,
        )
        Button(
            onClick = {
                scope.launch {
                    runCatching { backend.enterCode(code, stranger) }
                        .onSuccess { onDone() }
                        .onFailure { error = it.message }
                    code = ""
                }
            },
            enabled = code.length == 10,
        ) { Text(stringResource(R.string.pair)) }
    }
    error?.let { Text(it, color = MaterialTheme.colorScheme.error, modifier = Modifier.padding(top = 4.dp)) }
}
