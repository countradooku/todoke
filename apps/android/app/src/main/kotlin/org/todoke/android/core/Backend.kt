// What the app asks of the core, in one interface, so the screens run
// against the real core (CoreBackend) or a scripted one in tests. Every call
// blocks or suspends off the main thread; the screens never call the core
// directly.

package org.todoke.android.core

import android.net.Uri
import kotlinx.coroutines.flow.Flow
import org.todoke.ffi.Contact
import org.todoke.ffi.CoreEvent
import org.todoke.ffi.HistoryItem
import org.todoke.ffi.Offer
import org.todoke.ffi.Status
import org.todoke.ffi.Stranger
import org.todoke.ffi.Transfer
import org.todoke.ffi.UwbController

/** A QR pairing offer to draw: a square of modules, true for dark. `nfc`
 * serves the same offer to an NFC reader while it shows (tap to pair). */
class QrCode(
    val width: Int,
    private val modules: BooleanArray,
    val expiresAt: Long,
    val nfc: NfcTag? = null,
) {
    fun dark(x: Int, y: Int): Boolean = modules[y * width + x]
}

/** The tag an NFC reader reads while a QR offer shows (host card
 * emulation): command APDUs in, responses out. Close it when the offer
 * goes. */
interface NfcTag : AutoCloseable {
    fun respond(apdu: ByteArray): ByteArray

    override fun close() {}
}

/** A pairing code to show; the user reads it out to the other device. */
class PairingCode(val code: String, val expiresAt: Long)

/** A document the user picked, to offer under its name. */
class Picked(val uri: Uri, val name: String)

interface Backend {
    suspend fun status(): Status

    suspend fun contacts(): List<Contact>

    suspend fun transfers(): List<Transfer>

    suspend fun offers(): List<Offer>

    suspend fun history(): List<HistoryItem>

    suspend fun clearHistory()

    /** Shows a QR offer; its text never reaches the app. */
    suspend fun showQr(): QrCode

    /** Pairs with the device whose QR text was scanned. */
    suspend fun scanQr(text: String): String

    /** Pairs with the device whose NFC tag was read (its NDEF message). */
    suspend fun scanNfc(message: ByteArray): String

    suspend fun showCode(): PairingCode

    suspend fun strangers(): List<Stranger>

    suspend fun enterCode(code: String, stranger: String): String

    suspend fun stopPairing()

    suspend fun setHidden(hidden: Boolean)

    /** Offers documents the user picked to a contact; the transfer ID. */
    suspend fun send(contact: String, documents: List<Picked>): String

    suspend fun accept(transfer: String, files: List<UInt>)

    suspend fun decline(transfer: String)

    suspend fun cancel(transfer: String)

    /** This device can be pointed at with ultra-wideband now, or not. */
    suspend fun setRangingReady(ready: Boolean)

    /** Points at nearby contacts with these prepared controllers. */
    suspend fun pointStart(controllers: List<UwbController>)

    suspend fun pointStop()

    /** Ranges with `contact`, which points at this device, at `controlee`. */
    suspend fun acceptRanging(contact: String, sessionId: UInt, controlee: UShort)

    suspend fun refuseRanging(contact: String, sessionId: UInt)

    /** The core's events from now on; ends when the core stops. */
    fun events(): Flow<CoreEvent>
}
