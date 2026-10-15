// The process-wide state: the core, started once (off the main thread, after
// the user unlocks when the key is gated), the export of received files to
// the folder the user chose, and the settings the app keeps.

package org.todoke.android

import android.app.Application
import android.app.KeyguardManager
import android.net.Uri
import android.net.wifi.WifiManager
import java.io.File
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import org.todoke.android.core.AndroidKeyStore
import org.todoke.android.core.Backend
import org.todoke.android.core.Channels
import org.todoke.android.core.CoreBackend
import org.todoke.android.core.Exporter
import org.todoke.android.core.SafFolder
import org.todoke.android.core.TodokeNotifier
import org.todoke.ffi.Core
import org.todoke.ffi.CoreEvent
import org.todoke.ffi.Guarded
import org.todoke.ffi.KeyStoragePolicy
import org.todoke.ffi.KeyStoreError
import org.todoke.ffi.Settings
import org.todoke.ffi.TodokeError
import org.todoke.ffi.events

/** Where the core is. */
sealed interface CoreState {
    /** Not started; with `gated`, the user must unlock first. */
    data class Locked(val gated: Boolean) : CoreState

    data object Starting : CoreState

    data class Ready(val backend: Backend) : CoreState

    /** This build keeps sessions disabled (PROTOCOL §16). */
    data class Disabled(val message: String) : CoreState

    data class Failed(val message: String) : CoreState
}

class TodokeApplication : Application() {
    val prefs by lazy { Prefs(this) }

    private val _core = MutableStateFlow<CoreState>(CoreState.Locked(gated = false))
    val core: StateFlow<CoreState> get() = _core

    private var guarded: Guarded<Core>? = null

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    private val received by lazy { File(filesDir, "received") }

    private val exporter by lazy { Exporter(received) }

    override fun onCreate() {
        super.onCreate()
        Channels.create(this)
        // The key is gated when the device has a lock screen: decided once,
        // when the profile's key is made.
        if (!prefs.gateDecided) {
            prefs.gate = getSystemService(KeyguardManager::class.java).isDeviceSecure
            prefs.gateDecided = true
        }
        _core.value = testBackend?.let { CoreState.Ready(it) } ?: CoreState.Locked(prefs.gate)
    }

    fun backendOrNull(): Backend? = (_core.value as? CoreState.Ready)?.backend

    /** The start in progress, if any (guarded by `this`). */
    private var starting: Job? = null

    /**
     * Starts the core, once, and returns when it is ready or could not
     * start; call right after the user unlocked when gated. The start runs
     * in the app's scope: a caller that goes away (the screen that asked
     * leaves when the state changes) cannot strand it half done, and callers
     * at the same time (the activity, the resume worker) share one start.
     */
    suspend fun start() {
        val job = synchronized(this) {
            if (_core.value is CoreState.Ready) return
            starting?.takeIf { it.isActive } ?: scope.launch(Dispatchers.IO) { open() }.also { starting = it }
        }
        job.join()
    }

    private fun open() {
        _core.value = CoreState.Starting
        val keys = AndroidKeyStore(this, prefs.gate)
        _core.value = try {
            val settings = Settings(
                home = File(filesDir, "todoke").path,
                downloads = received.path,
                lan = true,
                allowLoopback = false,
                hidden = prefs.hidden,
                historyDays = 30u,
                keyStorage = KeyStoragePolicy.PLATFORM,
            )
            val core = Core(settings, keys)
            try {
                core.setNotifier(TodokeNotifier(this@TodokeApplication))
            } catch (error: Throwable) {
                // Never leave a core running that nothing holds: a retry
                // would start a second one on the same profile.
                core.close()
                throw error
            }
            val held = Guarded(core)
            guarded = held
            // mDNS discovery: Android drops multicast without this lock.
            getSystemService(WifiManager::class.java)?.createMulticastLock("todoke-discovery")?.run {
                setReferenceCounted(false)
                acquire()
            }
            // Whatever finished while the app was away, then each
            // incoming transfer as it ends.
            val backend = CoreBackend(held, this, exporter.receiving)
            scope.launch {
                exportReceived(backend)
                held.events().collect {
                    if (it is CoreEvent.Completed || it is CoreEvent.Ended) exportReceived(backend)
                }
            }
            CoreState.Ready(backend)
        } catch (error: TodokeError.Disabled) {
            CoreState.Disabled(error.message.orEmpty())
        } catch (error: TodokeError.KeyStore) {
            keyProblem(keys, error.message)
        } catch (error: KeyStoreError) {
            keyProblem(keys, error.message)
        } catch (error: TodokeError) {
            CoreState.Failed(error.message.orEmpty())
        }
    }

    /** Locked when the user has to unlock first; otherwise the key cannot
     * be used (gone, damaged, invalidated by removing the screen lock), and
     * asking again would not help: say why. */
    private fun keyProblem(keys: AndroidKeyStore, message: String?): CoreState =
        if (keys.refused) CoreState.Locked(prefs.gate) else CoreState.Failed(keys.problem ?: message.orEmpty())

    /** Moves received files to the folder the user chose, if they chose
     * one and nothing is being received. Failures (the folder gone, the
     * grant revoked) leave the files here for the next try. */
    fun exportReceived(backend: Backend? = backendOrNull()) {
        backend ?: return
        val tree = prefs.exportTree?.let(Uri::parse) ?: return
        scope.launch {
            runCatching { exporter.exportWhenQuiet(backend, SafFolder.tree(contentResolver, tree)) }
        }
    }

    companion object {
        /** A scripted core for the UI tests, set before the app starts. */
        @Volatile
        var testBackend: Backend? = null
    }
}

/** What the app remembers between runs (never anything secret). */
class Prefs(application: Application) {
    private val store = application.getSharedPreferences("todoke", android.content.Context.MODE_PRIVATE)

    var gate: Boolean
        get() = store.getBoolean("gate", false)
        set(value) = store.edit().putBoolean("gate", value).apply()

    var gateDecided: Boolean
        get() = store.getBoolean("gate-decided", false)
        set(value) = store.edit().putBoolean("gate-decided", value).apply()

    var hidden: Boolean
        get() = store.getBoolean("hidden", false)
        set(value) = store.edit().putBoolean("hidden", value).apply()

    /** The key Direct Share shortcut IDs are made with (random, made once;
     * it only keeps fingerprints out of the system's shortcut store). */
    @Synchronized
    fun shortcutKey(): ByteArray {
        store.getString("shortcut-key", null)?.let { return android.util.Base64.decode(it, android.util.Base64.NO_WRAP) }
        val key = ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }
        store.edit().putString("shortcut-key", android.util.Base64.encodeToString(key, android.util.Base64.NO_WRAP)).apply()
        return key
    }

    /** The folder received files are exported to (a SAF tree URI). */
    var exportTree: String?
        get() = store.getString("export-tree", null)
        set(value) = store.edit().putString("export-tree", value).apply()
}
