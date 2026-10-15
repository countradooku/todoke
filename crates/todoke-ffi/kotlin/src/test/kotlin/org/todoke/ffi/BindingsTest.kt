// The Kotlin bindings as the Android app uses them: start two cores, pair
// by QR, offer a file, see the offer on the event flow, accept it, see it
// arrive; typed errors; the key store hook; closing a core that is in use.

package org.todoke.ffi

import java.io.File
import java.nio.file.Files
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.flow.filterIsInstance
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout

@OptIn(ExperimentalUnsignedTypes::class)
class BindingsTest {
    private val scratch = mutableListOf<File>()

    private fun home(name: String): File =
        Files.createTempDirectory("todoke-kotlin-$name").toFile().also {
            File(it, "downloads").mkdirs()
            scratch += it
        }

    @AfterTest
    fun cleanUp() {
        scratch.forEach { it.deleteRecursively() }
    }

    private fun settings(home: File, keyStorage: KeyStoragePolicy = KeyStoragePolicy.FILE) =
        Settings(
            home = home.absolutePath,
            downloads = File(home, "downloads").absolutePath,
            lan = true,
            allowLoopback = true,
            hidden = false,
            historyDays = 7u,
            keyStorage = keyStorage,
        )

    /** A key store in memory, as the app keeps it in the Android Keystore. */
    private class MemoryKeyStore : KeyStore {
        @Volatile var key: ByteArray? = null

        override fun protection() = KeyProtection.STRONG_BOX

        override fun load(): ByteArray? = key

        @Synchronized
        override fun store(key: ByteArray) {
            if (this.key != null) throw KeyStoreError.AlreadyExists
            this.key = key.copyOf()
        }
    }

    @Test
    fun versionIsKnown() {
        assertTrue(Core.version().isNotEmpty())
    }

    @Test
    fun twoCoresPairOfferAcceptAndReceive() = runBlocking {
        val (homeA, homeB) = home("a") to home("b")
        Core(settings(homeA)).use { a ->
            val keys = MemoryKeyStore()
            Core(settings(homeB, KeyStoragePolicy.PLATFORM), keys).use { b ->
                assertEquals(KeyProtection.STRONG_BOX, b.status().keyProtection)
                assertEquals(32, keys.key?.size)

                // Collecting starts at once: no event is missed.
                val offered = async(start = CoroutineStart.UNDISPATCHED) {
                    withTimeout(60_000) {
                        a.events().filterIsInstance<CoreEvent.OfferReceived>().first().offer
                    }
                }
                val qr = a.pairShowQr()
                assertEquals((qr.width() * qr.width()).toInt(), qr.modules().size)
                assertTrue(qr.text().startsWith("TODOKE:"))
                val contact = b.pairScanQr(qr.text())
                assertEquals(a.status().device, contact.device())

                val file = File(homeB, "hello.txt").apply { writeText("hello from kotlin") }
                val sent = contact.send(listOf(file.absolutePath))
                val offer = offered.await()
                assertEquals(sent.id(), offer.transfer)
                assertEquals(listOf("hello.txt"), offer.entries.map { it.name })

                val completed = async(start = CoroutineStart.UNDISPATCHED) {
                    withTimeout(60_000) {
                        a.events().filterIsInstance<CoreEvent.Completed>()
                            .first { it.transfer == offer.transfer }
                    }
                }
                a.transfer(offer.transfer).accept(uintArrayOf())
                completed.await()
                assertEquals(
                    "hello from kotlin",
                    File(homeA, "downloads/hello.txt").readText(),
                )
            }
        }
    }

    @Test
    fun malformedRequestsAreTypedErrors() = runBlocking {
        Core(settings(home("errors"))).use { core ->
            assertFailsWith<TodokeError.Invalid> { core.contact("not hex") }
            assertFailsWith<TodokeError> {
                core.transfer("00".repeat(16)).accept(uintArrayOf())
            }
        }
        assertFailsWith<TodokeError.Invalid> {
            Core(settings(home("relative")).copy(home = "relative"))
        }
        Unit
    }

    @Test
    fun guardedCloseWaitsForCallsInProgress() = runBlocking(Dispatchers.Default) {
        val guarded = Guarded(Core(settings(home("guarded"))))
        val calls = (1..8).map { async { guarded.callSuspending { it.status() } } }
        // close() blocks while calls are in progress: off the callers' threads.
        withContext(Dispatchers.IO) { guarded.close() }
        calls.forEach { call -> runCatching { call.await() } }
        assertFailsWith<IllegalStateException> { guarded.call { it.contact("ab") } }
        Unit
    }
}
