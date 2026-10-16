// NFC tap-to-pair (PROTOCOL §3.1.1). While a QR offer shows, this device
// emulates a read-only NFC Forum Type 4 Tag (host card emulation) whose
// NDEF message carries the offer; the core answers every command, and the
// tag answers nothing once the offer is off screen. The scanning device
// reads it in reader mode and hands the NDEF message to the core, which
// checks it before pairing as from a scanned QR code.

package org.todoke.android.radio

import android.app.Activity
import android.content.ComponentName
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.cardemulation.CardEmulation
import android.nfc.cardemulation.HostApduService
import android.nfc.tech.Ndef
import android.os.Bundle
import org.todoke.android.core.NfcTag

object NfcPairing {
    @Volatile
    private var tag: NfcTag? = null

    /** "File or application not found": nothing is served now. */
    private val NOT_FOUND = byteArrayOf(0x6A, 0x82.toByte())

    /** Serves `tag` from now on (while its offer shows). */
    fun serve(tag: NfcTag) {
        this.tag = tag
    }

    /** Serves `tag` while the offer shows on `activity`, the preferred
     * service for its NDEF application while it is resumed. */
    fun serve(activity: Activity, tag: NfcTag) {
        serve(tag)
        runCatching {
            val adapter = NfcAdapter.getDefaultAdapter(activity) ?: return
            CardEmulation.getInstance(adapter)
                .setPreferredService(activity, ComponentName(activity, PairingTagService::class.java))
        }
    }

    /** The offer is off screen or gone: the tag answers nothing from now
     * on (its owner closes it). */
    fun withdraw(tag: NfcTag) {
        if (this.tag === tag) this.tag = null
    }

    /** As [withdraw], and `activity` is no longer the preferred service. */
    fun withdraw(activity: Activity, tag: NfcTag) {
        withdraw(tag)
        runCatching {
            val adapter = NfcAdapter.getDefaultAdapter(activity) ?: return
            CardEmulation.getInstance(adapter).unsetPreferredService(activity)
        }
    }

    internal fun respond(apdu: ByteArray): ByteArray =
        tag?.let { runCatching { it.respond(apdu) }.getOrNull() } ?: NOT_FOUND

    /** Reads tags on `activity` until the returned closer runs; `onMessage`
     * gets each NDEF message read (on a binder thread). */
    fun read(activity: Activity, onMessage: (ByteArray) -> Unit): () -> Unit {
        val adapter = NfcAdapter.getDefaultAdapter(activity) ?: return {}
        val callback = NfcAdapter.ReaderCallback { tag: Tag ->
            val message = runCatching {
                Ndef.get(tag)?.use { ndef ->
                    ndef.connect()
                    ndef.ndefMessage?.toByteArray()
                }
            }.getOrNull()
            message?.let(onMessage)
        }
        runCatching {
            adapter.enableReaderMode(activity, callback, NfcAdapter.FLAG_READER_NFC_A or NfcAdapter.FLAG_READER_NFC_B, Bundle())
        }
        return { runCatching { adapter.disableReaderMode(activity) } }
    }

    /** Whether this device can read or emulate tags now (NFC on). */
    fun enabled(activity: Activity): Boolean = NfcAdapter.getDefaultAdapter(activity)?.isEnabled == true
}

/** The emulated tag, routed by the system for the NDEF application. */
class PairingTagService : HostApduService() {
    override fun processCommandApdu(apdu: ByteArray, extras: Bundle?): ByteArray = NfcPairing.respond(apdu)

    override fun onDeactivated(reason: Int) {}
}
