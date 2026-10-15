// The process-wide state: the core, started once (off the main thread, after
// the user unlocks when the key is gated), and the settings the app keeps.

package org.todoke.android

import android.app.Application
import android.app.KeyguardManager
import android.net.wifi.WifiManager
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.withContext
import org.todoke.android.core.AndroidKeyStore
import org.todoke.android.core.Backend
import org.todoke.android.core.Channels
import org.todoke.android.core.CoreBackend
import org.todoke.android.core.TodokeNotifier
import org.todoke.ffi.Core
import org.todoke.ffi.Guarded
import org.todoke.ffi.KeyStoragePolicy
import org.todoke.ffi.KeyStoreError
import org.todoke.ffi.Settings
import org.todoke.ffi.TodokeError

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

    /** Starts the core; call right after the user unlocked when gated. */
    suspend fun start() {
        if (_core.value is CoreState.Ready || _core.value is CoreState.Starting) return
        _core.value = CoreState.Starting
        _core.value = withContext(Dispatchers.IO) {
            try {
                val settings = Settings(
                    home = File(filesDir, "todoke").path,
                    downloads = File(filesDir, "received").path,
                    lan = true,
                    allowLoopback = false,
                    hidden = prefs.hidden,
                    historyDays = 30u,
                    keyStorage = KeyStoragePolicy.PLATFORM,
                )
                val core = Core(settings, AndroidKeyStore(this@TodokeApplication, prefs.gate))
                core.setNotifier(TodokeNotifier(this@TodokeApplication))
                val held = Guarded(core)
                guarded = held
                // mDNS discovery: Android drops multicast without this lock.
                getSystemService(WifiManager::class.java)?.createMulticastLock("todoke-discovery")?.run {
                    setReferenceCounted(false)
                    acquire()
                }
                CoreState.Ready(CoreBackend(held, contentResolver))
            } catch (error: TodokeError.Disabled) {
                CoreState.Disabled(error.message.orEmpty())
            } catch (error: TodokeError.KeyStore) {
                CoreState.Locked(prefs.gate)
            } catch (error: KeyStoreError) {
                CoreState.Locked(prefs.gate)
            } catch (error: TodokeError) {
                CoreState.Failed(error.message.orEmpty())
            }
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

    /** The folder received files are exported to (a SAF tree URI). */
    var exportTree: String?
        get() = store.getString("export-tree", null)
        set(value) = store.edit().putString("export-tree", value).apply()
}
