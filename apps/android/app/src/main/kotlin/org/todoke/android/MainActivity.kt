// The one activity: unlocks (BiometricPrompt, when the key is gated) and
// starts the core, then shows the app. It also receives files shared from
// other apps (the share sheet and Direct Share shortcuts) and asks which
// contact gets them.

package org.todoke.android

import org.todoke.android.core.Picked
import org.todoke.android.core.Documents
import kotlinx.coroutines.withContext
import kotlinx.coroutines.Dispatchers
import androidx.compose.runtime.produceState
import android.content.Context
import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.ReportDrawnWhen
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
import androidx.biometric.BiometricPrompt
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.core.content.IntentCompat
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.viewmodel.compose.viewModel
import kotlinx.coroutines.launch
import org.todoke.android.core.ResumeWorker
import org.todoke.android.core.Shortcuts
import org.todoke.android.core.TransferService
import org.todoke.android.ui.AppRoot
import org.todoke.android.ui.AppViewModel
import org.todoke.android.ui.ShareSheet
import org.todoke.android.ui.TodokeTheme

class MainActivity : FragmentActivity() {
    private val app get() = application as TodokeApplication

    /** Files shared into the app, waiting for a contact. */
    private val shared = mutableStateOf<SharedFiles?>(null)

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        shared.value = SharedFiles.from(this, intent)
        setContent {
            TodokeTheme {
                Surface(Modifier.fillMaxSize()) { Content() }
            }
        }
        ResumeWorker.schedule(this)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        SharedFiles.from(this, intent)?.let { shared.value = it }
    }

    @Composable
    private fun Content() {
        val core by app.core.collectAsStateWithLifecycle()
        // Startup ends with the first screen that needs nothing more: the
        // app, an unlock request, or why the core did not start.
        ReportDrawnWhen {
            when (val state = core) {
                is CoreState.Locked -> state.gated
                CoreState.Starting -> false
                else -> true
            }
        }
        AskForNotifications()
        when (val state = core) {
            is CoreState.Locked -> Locked(state.gated)
            CoreState.Starting -> Message(stringResource(R.string.starting))
            is CoreState.Disabled -> Message(stringResource(R.string.sessions_disabled))
            is CoreState.Failed -> Message(state.message, retry = { lifecycleScope.launch { app.start() } })
            is CoreState.Ready -> {
                val model: AppViewModel = viewModel(factory = AppViewModel.Factory(state.backend))
                val ui by model.state.collectAsStateWithLifecycle()
                LaunchedEffect(ui.contacts) { Shortcuts.publish(this@MainActivity, ui.contacts) }
                AppRoot(model, onTransferStarted = { TransferService.start(this@MainActivity) })
                shared.value?.let { files ->
                    // Names come from the sharing app's provider: asked off
                    // the main thread, shown before anything is sent.
                    val picked by produceState<List<Picked>?>(null, files) {
                        value = withContext(Dispatchers.IO) { files.picked(this@MainActivity) }
                    }
                    ShareSheet(
                        contacts = ui.contacts,
                        names = picked?.map { it.name },
                        preselected = files.shortcut?.let { Shortcuts.contact(this@MainActivity, it, ui.contacts) },
                        onSend = { contact ->
                            picked?.let { documents ->
                                shared.value = null
                                model.send(contact, documents)
                                TransferService.start(this@MainActivity)
                            }
                        },
                        onDismiss = { shared.value = null },
                    )
                }
            }
        }
    }

    @Composable
    private fun Locked(gated: Boolean) {
        // Android 17 asks for the local network before the core starts: the
        // LAN needs it; without it only the relay works.
        val localNetwork = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) {
            if (gated) unlock() else lifecycleScope.launch { app.start() }
        }
        LaunchedEffect(gated) {
            if (Build.VERSION.SDK_INT >= ANDROID_17 &&
                ContextCompat.checkSelfPermission(this@MainActivity, LOCAL_NETWORK) != PackageManager.PERMISSION_GRANTED
            ) {
                localNetwork.launch(LOCAL_NETWORK)
            } else if (gated) {
                unlock()
            } else {
                app.start()
            }
        }
        Message(stringResource(R.string.locked), retry = if (gated) ({ unlock() }) else null)
    }

    private companion object {
        const val ANDROID_17 = 37
        const val LOCAL_NETWORK = "android.permission.ACCESS_LOCAL_NETWORK"
    }

    /** Asks the user to unlock (strong biometric or the device credential),
     * then starts the core while the Keystore key may be used. */
    private fun unlock() {
        val prompt = BiometricPrompt(
            this,
            ContextCompat.getMainExecutor(this),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    lifecycleScope.launch { app.start() }
                }
            },
        )
        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle(getString(R.string.unlock_title))
            .apply {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    setAllowedAuthenticators(BIOMETRIC_STRONG or DEVICE_CREDENTIAL)
                } else {
                    @Suppress("DEPRECATION")
                    setDeviceCredentialAllowed(true)
                }
            }
            .build()
        prompt.authenticate(info)
    }

    @Composable
    private fun AskForNotifications() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return
        val launcher = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) {}
        LaunchedEffect(Unit) {
            if (ContextCompat.checkSelfPermission(this@MainActivity, Manifest.permission.POST_NOTIFICATIONS) !=
                PackageManager.PERMISSION_GRANTED
            ) {
                launcher.launch(Manifest.permission.POST_NOTIFICATIONS)
            }
        }
    }

    @Composable
    private fun Message(text: String, retry: (() -> Unit)? = null) {
        Column(Modifier.fillMaxSize().safeDrawingPadding().padding(24.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
            Text(text, style = MaterialTheme.typography.titleMedium)
            retry?.let { Button(onClick = it) { Text(stringResource(R.string.retry)) } }
        }
    }
}

/** Files another app shared with todoke, and the Direct Share shortcut if
 * one was used. */
class SharedFiles(val uris: List<Uri>, val shortcut: String?) {
    fun picked(activity: MainActivity) = uris.map { Picked(it, org.todoke.android.ui.displayName(activity, it)) }

    companion object {
        /** What `intent` shares, keeping only other apps' content URIs
         * (never a file URI, never one of todoke's own providers). */
        fun from(context: Context, intent: Intent?): SharedFiles? {
            intent ?: return null
            val uris = when (intent.action) {
                Intent.ACTION_SEND -> listOfNotNull(IntentCompat.getParcelableExtra(intent, Intent.EXTRA_STREAM, Uri::class.java))
                Intent.ACTION_SEND_MULTIPLE ->
                    IntentCompat.getParcelableArrayListExtra(intent, Intent.EXTRA_STREAM, Uri::class.java).orEmpty()
                else -> return null
            }
            val shareable = uris.filter { Documents.shareable(context, it) }
            if (shareable.isEmpty()) return null
            return SharedFiles(shareable, intent.getStringExtra(Intent.EXTRA_SHORTCUT_ID))
        }
    }
}
