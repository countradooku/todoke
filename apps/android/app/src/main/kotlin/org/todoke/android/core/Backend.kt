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

/** A QR pairing offer to draw: a square of modules, true for dark. */
class QrCode(val width: Int, private val modules: BooleanArray, val expiresAt: Long) {
    fun dark(x: Int, y: Int): Boolean = modules[y * width + x]
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

    /** The core's events from now on; ends when the core stops. */
    fun events(): Flow<CoreEvent>
}
