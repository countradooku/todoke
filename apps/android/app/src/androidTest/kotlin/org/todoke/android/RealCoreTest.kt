// The real core inside the app's sandbox (its SELinux domain and seccomp
// filter, which a binary run from `adb shell` does not have): two cores in
// app-private storage pair by QR over loopback, one sends a document handed
// over open, the other accepts it and publishes it. This is the run that
// shows where Android refuses a system call (hard links in the app's data,
// renameat2 before Android 11). It needs the development libraries
// (unaudited-dev and test-support); with the release ones it is skipped.

@file:OptIn(ExperimentalUnsignedTypes::class)

package org.todoke.android

import android.net.Uri
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import java.security.KeyStore as JavaKeyStore
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.flow.filterIsInstance
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assume.assumeNoException
import org.junit.Test
import org.junit.runner.RunWith
import org.todoke.android.core.AndroidKeyStore
import org.todoke.android.core.CoreBackend
import org.todoke.android.core.Picked
import org.todoke.ffi.Core
import org.todoke.ffi.CoreEvent
import org.todoke.ffi.Guarded
import org.todoke.ffi.KeyStoragePolicy
import org.todoke.ffi.Settings
import org.todoke.ffi.TodokeError
import org.todoke.ffi.events

@RunWith(AndroidJUnit4::class)
class RealCoreTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val scratch = File(context.noBackupFilesDir, "real-core-test")

    @After
    fun cleanUp() {
        // The Keystore keys this test made, by the profiles' IDs.
        val keystore = JavaKeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        scratch.walk().filter { it.name == "storage.id" }.forEach { keystore.deleteEntry("todoke-storage-${it.readText().trim()}") }
        scratch.deleteRecursively()
    }

    private fun settings(name: String, keyStorage: KeyStoragePolicy): Settings {
        val home = File(scratch, name).apply { mkdirs() }
        return Settings(
            home = home.absolutePath,
            downloads = File(home, "received").apply { mkdirs() }.absolutePath,
            lan = true,
            allowLoopback = true,
            hidden = false,
            historyDays = 7u,
            keyStorage = keyStorage,
        )
    }

    /** A core, or the test is skipped when these libraries cannot run one. */
    private fun core(settings: Settings, keys: AndroidKeyStore? = null): Core = try {
        if (keys == null) Core(settings) else Core(settings, keys)
    } catch (error: TodokeError.Disabled) {
        assumeNoException("release libraries start no core", error)
        throw error
    } catch (error: TodokeError.Invalid) {
        assumeNoException("these libraries have no loopback discovery", error)
        throw error
    }

    @Test
    fun aDocumentHandedOverOpenArrivesInAppStorage() = runBlocking(Dispatchers.IO) {
        val receiving = settings("a", KeyStoragePolicy.FILE)
        val sending = settings("b", KeyStoragePolicy.PLATFORM)
        Guarded(core(receiving)).use { a ->
            // The sender's storage key lives in the Android Keystore.
            Guarded(core(sending, AndroidKeyStore(context, gated = false))).use { b ->
                val offered = async(start = CoroutineStart.UNDISPATCHED) {
                    withTimeout(60_000) { a.events().filterIsInstance<CoreEvent.OfferReceived>().first().offer }
                }
                val text = a.call { it.pairShowQr() }.use { it.text() }
                val device = b.call { it.pairScanQr(text) }.use { it.device() }

                val backend = CoreBackend(b, context)
                // The app's own files are never sent, whatever names them.
                val own = File(context.filesDir, "notes.txt").apply { writeText("private") }
                assertThrows(SecurityException::class.java) {
                    runBlocking { backend.send(device, listOf(Picked(Uri.fromFile(own), "notes.txt"))) }
                }
                own.delete()
                // Outside the app's data (app-specific external storage).
                val document = File(context.getExternalFilesDir(null), "notes.txt").apply { writeText("hello from the sandbox") }
                // Kept until the transfer ends: the sender refuses a file that
                // changes (or goes) while it is offered.
                val sent = backend.send(device, listOf(Picked(Uri.fromFile(document), "trip notes.txt")))
                val offer = offered.await()
                assertEquals(sent, offer.transfer)
                assertEquals(listOf("trip notes.txt"), offer.entries.map { it.name })

                val completed = async(start = CoroutineStart.UNDISPATCHED) {
                    withTimeout(60_000) {
                        a.events().filterIsInstance<CoreEvent.Completed>().first { it.transfer == offer.transfer }
                    }
                }
                a.call { it.transfer(offer.transfer) }.use { it.accept(uintArrayOf()) }
                completed.await()
                document.delete()
                assertEquals("hello from the sandbox", File(receiving.downloads, "trip notes.txt").readText())
            }
        }
    }
}
