// The Kotlin bindings as the Android app uses them: start two cores, pair
// by QR, offer a file, see the offer on the event flow, accept it, see it
// arrive; typed errors; the key store hook and its policy; Guarded closing
// objects in use. Commands block: the tests call them on Dispatchers.IO.
// With TODOKE_RELEASE=1 (a library built without development sessions)
// only the release check runs.

package org.todoke.ffi

import java.io.File
import java.nio.file.Files
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.flow.filterIsInstance
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import org.junit.jupiter.api.Assumptions.assumeFalse
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.TestInfo

private val releaseLibrary = System.getenv("TODOKE_RELEASE") == "1"

@OptIn(ExperimentalUnsignedTypes::class)
class BindingsTest {
    private val scratch = mutableListOf<File>()

    private fun home(name: String): File =
        Files.createTempDirectory("todoke-kotlin-$name").toFile().also {
            File(it, "downloads").mkdirs()
            scratch += it
        }

    @BeforeEach
    fun onlyTheReleaseCheckOnARelease(test: TestInfo) {
        if (test.testMethod.map { it.name } != java.util.Optional.of("releaseBuildsRefuseToStart")) {
            assumeFalse(releaseLibrary, "the release library starts no core")
        }
    }

    @AfterTest
    fun cleanUp() {
        scratch.forEach { it.deleteRecursively() }
    }

    private fun settings(
        home: File,
        keyStorage: KeyStoragePolicy = KeyStoragePolicy.FILE,
        loopback: Boolean = true,
    ) = Settings(
        home = home.absolutePath,
        downloads = File(home, "downloads").absolutePath,
        lan = true,
        allowLoopback = loopback,
        hidden = false,
        historyDays = 7u,
        keyStorage = keyStorage,
    )

    /** A key store in memory, as the app keeps keys in the Android Keystore. */
    private class MemoryKeyStore : KeyStore {
        val keys = java.util.concurrent.ConcurrentHashMap<String, ByteArray>()

        override fun protection() = KeyProtection.STRONG_BOX

        override fun load(profile: String): ByteArray? = keys[profile]?.copyOf()

        override fun store(profile: String, key: ByteArray) {
            if (keys.putIfAbsent(profile, key.copyOf()) != null) throw KeyStoreError.AlreadyExists
        }
    }

    /** A key store whose slot was wiped: all zeros. */
    private class WipedKeyStore : KeyStore {
        override fun protection() = KeyProtection.TEE

        override fun load(profile: String): ByteArray = ByteArray(32)

        override fun store(profile: String, key: ByteArray): Unit = throw KeyStoreError.AlreadyExists
    }

    /** A key store whose answers are fixed: a key of any length, or an error, declared or not. */
    private class CannedKeyStore(
        private val loaded: () -> ByteArray?,
        private val stored: () -> Unit,
    ) : KeyStore {
        override fun protection() = KeyProtection.TEE

        override fun load(profile: String): ByteArray? = loaded()

        override fun store(profile: String, key: ByteArray) = stored()
    }

    /** What the notifier was told, in order. */
    private class RecordingNotifier : Notifier {
        val log: MutableList<String> = java.util.Collections.synchronizedList(mutableListOf())

        override fun offerReceived(notice: OfferNotice) {
            log += "offer ${notice.transfer} from ${notice.from} ${notice.files} files " +
                "${notice.folders} folders ${notice.totalBytes} bytes"
        }

        override fun offerGone(transfer: String) {
            log += "gone $transfer"
        }

        override fun transferFinished(transfer: String, text: String) {
            log += "finished $transfer: $text"
        }

        override fun missed() {
            log += "missed"
        }
    }

    @Test
    fun versionIsKnown() {
        assertTrue(Core.version().isNotEmpty())
    }

    @Test
    fun twoCoresPairOfferAcceptAndReceive() = runBlocking(Dispatchers.IO) {
        val (homeA, homeB) = home("a") to home("b")
        val keys = MemoryKeyStore()
        Guarded(Core(settings(homeA))).use { a ->
            Guarded(Core(settings(homeB, KeyStoragePolicy.PLATFORM), keys)).use { b ->
                assertEquals(KeyProtection.STRONG_BOX, b.call { it.status() }.keyProtection)
                assertEquals(listOf(32), keys.keys.values.map { it.size })
                assertEquals(listOf(32), keys.keys.keys.map { it.length })

                // Collecting starts at once: no event is missed.
                val offered = async(start = CoroutineStart.UNDISPATCHED) {
                    withTimeout(60_000) {
                        a.events().filterIsInstance<CoreEvent.OfferReceived>().first().offer
                    }
                }
                val text = a.call { it.pairShowQr() }.use { qr ->
                    assertEquals((qr.width() * qr.width()).toInt(), qr.modules().size)
                    qr.text()
                }
                assertTrue(text.startsWith("TODOKE:"))
                val contact = b.call { it.pairScanQr(text) }
                assertEquals(a.call { it.status() }.device, contact.device())

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
                a.call { it.transfer(offer.transfer) }.use { it.accept(uintArrayOf()) }
                completed.await()
                assertEquals("hello from kotlin", File(homeA, "downloads/hello.txt").readText())
                sent.close()
                contact.close()
            }
        }
    }

    /** Closing a core stops it: its profile can be opened again. */
    @Test
    fun closingACoreFreesItsProfile() = runBlocking(Dispatchers.IO) {
        val home = home("reopen")
        Core(settings(home)).close()
        Core(settings(home)).close()
    }

    @Test
    fun theEventFlowEndsWhenTheCoreStops() = runBlocking(Dispatchers.IO) {
        val core = Guarded(Core(settings(home("flow"))))
        val collected = async(start = CoroutineStart.UNDISPATCHED) {
            withTimeout(60_000) { core.events().toList() }
        }
        core.closeSuspending()
        assertTrue(collected.await().none { it is CoreEvent.OfferReceived })
    }

    @Test
    fun malformedRequestsAreTypedErrors() = runBlocking(Dispatchers.IO) {
        Core(settings(home("errors"))).use { core ->
            assertFailsWith<TodokeError.Invalid> { core.contact("not hex") }
            assertFailsWith<TodokeError> {
                core.transfer("00".repeat(16)).use { it.accept(uintArrayOf()) }
            }
        }
        assertFailsWith<TodokeError.Invalid> {
            Core(settings(home("relative")).copy(home = "relative"))
        }
        Unit
    }

    @Test
    fun keyStorePolicyAndWipedKeys() = runBlocking(Dispatchers.IO) {
        val home = home("keys")
        for (policy in listOf(KeyStoragePolicy.FILE, KeyStoragePolicy.AUTO)) {
            assertFailsWith<TodokeError.Invalid> { Core(settings(home, policy), MemoryKeyStore()) }
        }
        assertFailsWith<TodokeError.KeyStore> {
            Core(settings(home, KeyStoragePolicy.PLATFORM), WipedKeyStore())
        }
        Unit
    }

    @Test
    fun subscriptionsAreBoundedAndStop() = runBlocking(Dispatchers.IO) {
        Core(settings(home("subscriptions"))).use { core ->
            val held = mutableListOf<Events>()
            while (held.size <= 64) {
                try {
                    held += core.subscribe()
                } catch (_: TodokeError.State) {
                    break
                }
            }
            assertTrue(held.size < 64)
            held[0].stop()
            assertFailsWith<TodokeError.State> { held[0].next(1u, 0u) }
            core.subscribe().close()
            held.forEach { it.close() }
        }
    }

    @Test
    fun guardedCloseWaitsForCallsInProgress() = runBlocking(Dispatchers.Default) {
        val guarded = Guarded(Core(settings(home("guarded"))))
        // A call that starts after close is refused; the others finish first.
        val calls = (1..8).map {
            async(Dispatchers.IO) { runCatching { guarded.call { it.status() } } }
        }
        guarded.closeSuspending()
        for (outcome in calls.map { it.await() }) {
            val error = outcome.exceptionOrNull()
            assertTrue(error == null || error is IllegalStateException, "$error")
        }
        assertFailsWith<IllegalStateException> { guarded.call { it.contact("ab") } }
        // A second close waits for the free and returns.
        guarded.close()
    }

    @Test
    fun guardedRefusesToCloseFromInsideACall() = runBlocking(Dispatchers.IO) {
        val guarded = Guarded(Core(settings(home("reentrant"))))
        assertFailsWith<IllegalStateException> { guarded.call { guarded.close() } }
        assertFailsWith<IllegalStateException> {
            guarded.callSuspending { guarded.closeSuspending() }
        }
        guarded.closeSuspending()
    }

    /** A close waiting for a call is not cut short by an interrupt. */
    @Test
    fun guardedCloseOutlastsAnInterrupt() {
        val closed = AtomicBoolean(false)
        val guarded = Guarded(AutoCloseable { closed.set(true) })
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val caller = thread { guarded.call { entered.countDown(); release.await() } }
        assertTrue(entered.await(10, TimeUnit.SECONDS))
        var interruptedAfter = false
        val closer = thread {
            guarded.close()
            interruptedAfter = Thread.currentThread().isInterrupted
        }
        Thread.sleep(50)
        closer.interrupt()
        Thread.sleep(50)
        assertFalse(closed.get(), "freed during a call")
        release.countDown()
        caller.join(10_000)
        closer.join(10_000)
        assertTrue(closed.get())
        assertTrue(interruptedAfter, "the interrupt was lost")
    }

    /**
     * The notifier hears of an offer by its sender and counts, never a file
     * name, then of its notification going and the transfer ending.
     */
    @Test
    fun notifierHearsOffersWithoutNames() = runBlocking(Dispatchers.IO) {
        val (homeA, homeB) = home("notify-a") to home("notify-b")
        Guarded(Core(settings(homeA))).use { a ->
            Guarded(Core(settings(homeB))).use { b ->
                val told = RecordingNotifier()
                a.call { it.setNotifier(told) }
                val offered = async(start = CoroutineStart.UNDISPATCHED) {
                    withTimeout(60_000) {
                        a.events().filterIsInstance<CoreEvent.OfferReceived>().first().offer
                    }
                }
                val text = a.call { it.pairShowQr() }.use { it.text() }
                val contact = b.call { it.pairScanQr(text) }
                val file = File(homeB, "secret-plan.txt").apply { writeText("plans") }
                val sent = contact.send(listOf(file.absolutePath))
                val offer = offered.await()
                a.call { it.transfer(offer.transfer) }.use { it.accept(uintArrayOf()) }
                val finished = "finished ${sent.id()}: Files received"
                withTimeout(60_000) {
                    while (finished !in told.log.toList()) kotlinx.coroutines.delay(20)
                }
                val device = b.call { it.status() }.device
                assertEquals(
                    listOf(
                        "offer ${sent.id()} from $device 1 files 0 folders 5 bytes",
                        "gone ${sent.id()}",
                        finished,
                    ),
                    told.log.toList(),
                )
                assertTrue(told.log.none { it.contains("secret") })
                a.call { it.clearNotifier() }
                sent.close()
                contact.close()
            }
        }
    }

    /**
     * A key store that throws something it does not declare, or hands back
     * something that is not a key, stops the start with a key store error;
     * one that refuses (the user did not unlock) with Locked.
     */
    @Test
    fun failingKeyStoresStopTheStart() = runBlocking(Dispatchers.IO) {
        // Refused: the user did not unlock; the app asks again.
        assertFailsWith<TodokeError.Locked> {
            Core(
                settings(home("refusing"), KeyStoragePolicy.PLATFORM),
                CannedKeyStore({ null }, { throw KeyStoreError.Refused("no") }),
            )
        }
        val stores = listOf(
            CannedKeyStore({ null }, { throw IllegalStateException("undeclared") }),
            CannedKeyStore({ throw IllegalStateException("undeclared") }, {}),
            CannedKeyStore({ throw KeyStoreError.Unavailable("locked") }, {}),
            CannedKeyStore({ ByteArray(0) }, {}),
            CannedKeyStore({ ByteArray(31) { 7 } }, {}),
            CannedKeyStore({ ByteArray(33) { 7 } }, {}),
        )
        for (store in stores) {
            assertFailsWith<TodokeError.KeyStore> {
                Core(settings(home("failing"), KeyStoragePolicy.PLATFORM), store)
            }
        }
    }

    /** A profile reopened with its key store finds its key: the same identity, no second key. */
    @Test
    fun aProfileReopensWithItsKey() = runBlocking(Dispatchers.IO) {
        val home = home("reopen-keys")
        val keys = MemoryKeyStore()
        val device = Core(settings(home, KeyStoragePolicy.PLATFORM), keys).use { it.status().device }
        Core(settings(home, KeyStoragePolicy.PLATFORM), keys).use {
            assertEquals(device, it.status().device)
        }
        assertEquals(1, keys.keys.size)
    }

    /** The app gives the core its links once; a second time is refused. */
    @Test
    fun linksAreGivenOnce() = runBlocking(Dispatchers.IO) {
        val links = object : WifiLinks {
            override fun abilities() = LinkAbilities(emptyList(), emptyList(), emptyList())

            override fun host(request: LinkRequest): LinkLease = throw LinkError.Closed

            override fun join(request: LinkRequest): LinkLease = throw LinkError.Closed

            override fun bindSocket(lease: ULong, socket: Long): Unit = throw LinkError.Closed

            override fun release(lease: ULong) = Unit
        }
        Core(settings(home("links"))).use { core ->
            core.setLinks(links)
            assertFailsWith<TodokeError.State> { core.setLinks(links) }
        }
    }

    /** Pointing checks its parameters as the records will (PROTOCOL §10.4). */
    @Test
    fun pointingParametersAreChecked() = runBlocking(Dispatchers.IO) {
        Core(settings(home("point"))).use { core ->
            core.setRangingReady(1u)
            assertFailsWith<TodokeError.Invalid> { core.setRangingReady(0u) }
            assertFailsWith<TodokeError.Invalid> { core.setRangingReady(2u) }
            core.clearRangingReady()
            assertFailsWith<TodokeError.Invalid> { core.pointStart(emptyList()) }
            assertFailsWith<TodokeError.Invalid> { core.pointStart(listOf(UwbController(7u, 6u, 10u))) }
            core.pointStart(listOf(UwbController(7u, 9u, 10u), UwbController(8u, 5u, 9u)))
            assertFailsWith<TodokeError> { core.refuseRanging("ab".repeat(32), 1u) }
            core.pointStop()
        }
    }

    /** B pairs with A by tapping: A's emulated tag serves its QR offer. */
    @Test
    fun pairingByNfc() = runBlocking(Dispatchers.IO) {
        Guarded(Core(settings(home("nfc-a")))).use { a ->
            Guarded(Core(settings(home("nfc-b")))).use { b ->
                assertFailsWith<TodokeError.Pairing> { b.call { it.pairScanNfc(ByteArray(8)) } }
                val message = a.call { it.pairShowQr() }.use { qr ->
                    qr.nfcTag().use { tag -> readTag(tag) }
                }
                val contact = b.call { it.pairScanNfc(message) }
                assertEquals(a.call { it.status() }.device, contact.device())
                contact.close()
            }
        }
    }

    /** What a reader does with a Type 4 tag: select, read the length, read. */
    private fun readTag(tag: NfcTag): ByteArray {
        fun answer(vararg apdu: Int): ByteArray {
            val out = tag.respond(ByteArray(apdu.size) { apdu[it].toByte() })
            assertEquals(listOf(0x90.toByte(), 0), out.takeLast(2))
            return out.copyOf(out.size - 2)
        }
        answer(0, 0xa4, 4, 0, 7, 0xd2, 0x76, 0, 0, 0x85, 1, 1)
        answer(0, 0xa4, 0, 0x0c, 2, 0xe1, 0x04)
        val head = answer(0, 0xb0, 0, 0, 2)
        val length = (head[0].toInt() and 0xff shl 8) or (head[1].toInt() and 0xff)
        val message = java.io.ByteArrayOutputStream()
        while (message.size() < length) {
            val at = message.size() + 2
            val wanted = minOf(length - message.size(), 255)
            message.write(answer(0, 0xb0, at shr 8, at and 0xff, wanted))
        }
        return message.toByteArray()
    }

    /** A library built without development sessions starts no core. */
    @Test
    fun releaseBuildsRefuseToStart() {
        assumeTrue(releaseLibrary, "the test library starts cores")
        val home = home("shipped")
        assertFailsWith<TodokeError.Disabled> { Core(settings(home, loopback = false)) }
        assertFailsWith<TodokeError.Disabled> {
            Core(settings(home, KeyStoragePolicy.PLATFORM, loopback = false), MemoryKeyStore())
        }
    }
}
