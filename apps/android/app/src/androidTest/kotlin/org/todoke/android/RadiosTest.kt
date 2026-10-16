// The app's radios without radios: NFC tap-to-pair between two real cores
// through the emulated tag's service; pointing answering, ranging, and
// stopping with a scripted core and ultra-wideband; direct links taking no
// part without their permission or a reason to run.

@file:OptIn(ExperimentalUnsignedTypes::class)

package org.todoke.android

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeNoException
import org.junit.Test
import org.junit.runner.RunWith
import org.todoke.android.core.CoreBackend
import org.todoke.android.radio.AndroidLinks
import org.todoke.android.radio.Bearing
import org.todoke.android.radio.NfcPairing
import org.todoke.android.radio.PairingTagService
import org.todoke.android.radio.Pointing
import org.todoke.android.radio.Uwb
import org.todoke.ffi.Core
import org.todoke.ffi.CoreEvent
import org.todoke.ffi.Guarded
import org.todoke.ffi.KeyStoragePolicy
import org.todoke.ffi.LinkError
import org.todoke.ffi.LinkKind
import org.todoke.ffi.LinkRequest
import org.todoke.ffi.LinkSecurity
import org.todoke.ffi.RangingInfo
import org.todoke.ffi.Settings
import org.todoke.ffi.TodokeError
import org.todoke.ffi.UwbController

@RunWith(AndroidJUnit4::class)
class RadiosTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val scratch = File(context.noBackupFilesDir, "radios-test")

    @After
    fun cleanUp() {
        scratch.deleteRecursively()
    }

    private fun core(name: String): Core {
        val home = File(scratch, name).apply { mkdirs() }
        val settings = Settings(
            home = home.absolutePath,
            downloads = File(home, "received").apply { mkdirs() }.absolutePath,
            lan = true,
            allowLoopback = true,
            hidden = false,
            historyDays = 7u,
            keyStorage = KeyStoragePolicy.FILE,
        )
        return try {
            Core(settings)
        } catch (error: TodokeError) {
            assumeNoException("these libraries start no core with loopback", error)
            throw error
        }
    }

    /** What a phone's reader does: select the NDEF application and file,
     * read the length, then the message, through the tag service. */
    private fun read(service: PairingTagService): ByteArray {
        fun answer(vararg apdu: Int): ByteArray {
            val out = service.processCommandApdu(ByteArray(apdu.size) { apdu[it].toByte() }, null)
            assertArrayEquals(byteArrayOf(0x90.toByte(), 0), out.copyOfRange(out.size - 2, out.size))
            return out.copyOf(out.size - 2)
        }
        answer(0, 0xa4, 4, 0, 7, 0xd2, 0x76, 0, 0, 0x85, 1, 1)
        answer(0, 0xa4, 0, 0x0c, 2, 0xe1, 0x04)
        val head = answer(0, 0xb0, 0, 0, 2)
        val length = (head[0].toInt() and 0xff shl 8) or (head[1].toInt() and 0xff)
        val message = java.io.ByteArrayOutputStream()
        while (message.size() < length) {
            val at = message.size() + 2
            message.write(answer(0, 0xb0, at shr 8, at and 0xff, minOf(length - message.size(), 255)))
        }
        return message.toByteArray()
    }

    @Test
    fun twoCoresPairByTapping() = runBlocking(Dispatchers.IO) {
        Guarded(core("a")).use { a ->
            Guarded(core("b")).use { b ->
                val shower = CoreBackend(a, context)
                val scanner = CoreBackend(b, context)
                // A service is made on the main thread (it makes a handler).
                var made: PairingTagService? = null
                InstrumentationRegistry.getInstrumentation().runOnMainSync { made = PairingTagService() }
                val service = made ?: error("no tag service")
                // Nothing shows: the tag answers "not found".
                assertArrayEquals(byteArrayOf(0x6A, 0x82.toByte()), service.processCommandApdu(byteArrayOf(0, 0xa4.toByte(), 4, 0), null))
                val qr = shower.showQr()
                val tag = qr.nfc ?: error("no NFC tag for the offer")
                NfcPairing.serve(tag)
                val message = read(service)
                NfcPairing.withdraw(tag)
                tag.close()
                assertArrayEquals(byteArrayOf(0x6A, 0x82.toByte()), service.processCommandApdu(byteArrayOf(0, 0xa4.toByte(), 4, 0), null))
                val device = scanner.scanNfc(message)
                assertEquals(shower.status().device, device)
            }
        }
    }

    private fun ranging(session: UInt, controller: UShort, controlee: UShort?) = RangingInfo(
        contact = "c1".repeat(32),
        sessionId = session,
        controller = controller,
        controlee = controlee,
        channel = 9u,
        preamble = 10u,
        config = 1u,
        stsKey = ByteArray(16) { 7 },
    )

    private suspend fun FakeBackend.waitFor(request: String) = withTimeout(5_000) {
        while (request !in requests) delay(20)
    }

    @Test
    fun pointingAnswersRangesAndStops() = runBlocking {
        val backend = FakeBackend()
        val uwb = FakeUwb()
        val foreground = MutableStateFlow(true)
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        try {
            val pointing = Pointing(backend, uwb, foreground, { true }, scope)
            backend.waitFor("ranging-ready true")
            withTimeout(5_000) { while (backend.events.subscriptionCount.value == 0) delay(20) }
            // A contact points here: a fresh controlee address answers it.
            backend.events.emit(CoreEvent.RangingRequested(ranging(7u, 0x1111u, null)))
            backend.waitFor("accept-ranging 7 ${0x2222}")
            withTimeout(5_000) { while ("controlee ${0x1111} ${0x2222}" !in uwb.ranged) delay(20) }
            // Pointing: one controller per nearby contact; a target ranges
            // and shows where it is until its ranging stops.
            pointing.start(2)
            backend.waitFor("point-start [${0x1111}, ${0x1112}]")
            backend.events.emit(CoreEvent.PointTarget(ranging(9u, 0x1111u, 0x3333u)))
            val bearings = withTimeout(5_000) { pointing.bearings.first { it.isNotEmpty() } }
            assertEquals(1.5f, bearings.values.single().meters)
            backend.events.emit(CoreEvent.RangingStopped("c1".repeat(32), 9u))
            withTimeout(5_000) { pointing.bearings.first { it.isEmpty() } }
            pointing.stop()
            backend.waitFor("point-stop")
            // In the background: not pointable, and a request is refused.
            foreground.value = false
            backend.waitFor("ranging-ready false")
            backend.events.emit(CoreEvent.RangingRequested(ranging(11u, 0x1111u, null)))
            backend.waitFor("refuse-ranging 11")
        } finally {
            scope.cancel()
        }
    }

    @Test
    fun linksTakeNoPartWithoutAReason() {
        val request = LinkRequest(LinkKind.WIFI_DIRECT, LinkSecurity.WPA2, "DIRECT-ab-tdk-0011223344556677", ByteArray(63) { 'a'.code.toByte() }, ByteArray(0), 1_000u)
        // Nothing runs: no abilities, and nothing is brought up.
        val idle = AndroidLinks(context) { false }
        assertTrue(idle.abilities().host.isEmpty() && idle.abilities().join.isEmpty())
        assertTrue(runCatching { idle.join(request) }.exceptionOrNull() is LinkError.Failed)
        // The secret is wiped once handled, even when nothing came up.
        assertTrue(request.secret.all { it == 0.toByte() })
        val active = AndroidLinks(context) { true }
        val secret = ByteArray(63) { 'a'.code.toByte() }
        runCatching { active.host(request.copy(kind = LinkKind.HOTSPOT, secret = secret)) }
        assertTrue(secret.all { it == 0.toByte() })
        // Unknown leases: nothing to bind, nothing to release.
        assertTrue(runCatching { active.bindSocket(99u, 3) }.exceptionOrNull() is LinkError.Closed)
        active.release(99u)
        // Without the permission for nearby Wi-Fi devices, no part at all.
        if (!org.todoke.android.radio.NearbyPermissions.wifiGranted(context)) {
            assertTrue(active.abilities().host.isEmpty() && active.abilities().join.isEmpty())
        }
    }
}

/** A scripted UWB: fixed addresses, one bearing per ranging. */
internal class FakeUwb : Uwb {
    @Volatile var on = true
    val ranged = java.util.Collections.synchronizedList(mutableListOf<String>())

    override suspend fun available() = on

    override suspend fun controllers(count: Int) = (1..count).map { UwbController((0x1110 + it).toUShort(), 9u, 10u) }

    override fun controller(target: RangingInfo): Flow<Bearing> = flow {
        ranged += "controller ${target.controller} ${target.controlee}"
        emit(Bearing(target.contact, 1.5f, 3f))
        delay(Long.MAX_VALUE)
    }

    override suspend fun controlee(): UShort = 0x2222u

    override fun controlee(ranging: RangingInfo, address: UShort): Flow<Bearing> = flow {
        ranged += "controlee ${ranging.controller} $address"
        delay(Long.MAX_VALUE)
    }

    override fun discard(address: UShort) {}

    override fun forget() {}
}
