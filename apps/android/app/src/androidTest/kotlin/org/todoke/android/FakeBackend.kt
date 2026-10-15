// A scripted core for the UI tests: fixed answers, recorded requests, and
// events the test injects.

@file:OptIn(ExperimentalUnsignedTypes::class)

package org.todoke.android

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import org.todoke.android.core.Backend
import org.todoke.android.core.PairingCode
import org.todoke.android.core.Picked
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import org.todoke.android.core.QrCode
import org.todoke.ffi.Contact
import org.todoke.ffi.CoreEvent
import org.todoke.ffi.Entry
import org.todoke.ffi.HistoryItem
import org.todoke.ffi.KeyProtection
import org.todoke.ffi.Offer
import org.todoke.ffi.Route
import org.todoke.ffi.Status
import org.todoke.ffi.Stranger
import org.todoke.ffi.Transfer
import org.todoke.ffi.TransferState
import org.todoke.ffi.Way

class FakeBackend : Backend {
    val requests = java.util.Collections.synchronizedList(mutableListOf<String>())
    val events = MutableSharedFlow<CoreEvent>(extraBufferCapacity = 16)

    @Volatile var contacts = listOf(contact("a1", "Pixel", available = true, nearby = true))

    @Volatile var transfers = emptyList<Transfer>()

    @Volatile var offers = emptyList<Offer>()

    @Volatile var history = emptyList<HistoryItem>()

    @Volatile var strangers = emptyList<Stranger>()

    @Volatile var hidden = false

    override suspend fun status() = Status(
        device = "f0".repeat(32),
        sessionsEnabled = true,
        contacts = contacts.size.toUInt(),
        sessions = 0u,
        pairing = false,
        hidden = hidden,
        historyDays = 30u,
        keyProtection = KeyProtection.STRONG_BOX,
    )

    override suspend fun contacts() = contacts

    override suspend fun transfers() = transfers

    override suspend fun offers() = offers

    override suspend fun history() = history

    override suspend fun clearHistory() {
        requests += "clear-history"
        history = emptyList()
    }

    override suspend fun showQr(): QrCode {
        requests += "show-qr"
        val matrix = QRCodeWriter().encode(
            "TODOKE:" + "0".repeat(120), BarcodeFormat.QR_CODE, 0, 0, mapOf(EncodeHintType.MARGIN to 0),
        )
        return QrCode(matrix.width, BooleanArray(matrix.width * matrix.width) { matrix[it % matrix.width, it / matrix.width] }, 0L)
    }

    override suspend fun scanQr(text: String): String {
        requests += "scan-qr"
        return "b2".repeat(32)
    }

    override suspend fun showCode(): PairingCode {
        requests += "show-code"
        return PairingCode("0123456789", 0L)
    }

    override suspend fun strangers() = strangers

    override suspend fun enterCode(code: String, stranger: String): String {
        requests += "enter-code $code $stranger"
        return "c3".repeat(32)
    }

    override suspend fun stopPairing() {
        requests += "stop-pairing"
    }

    override suspend fun setHidden(hidden: Boolean) {
        requests += "hidden $hidden"
        this.hidden = hidden
    }

    override suspend fun send(contact: String, documents: List<Picked>): String {
        requests += "send $contact ${documents.size}"
        return "d4".repeat(16)
    }

    override suspend fun accept(transfer: String, files: List<UInt>) {
        requests += "accept $transfer ${files.joinToString(",")}"
        offers = offers.filter { it.transfer != transfer }
    }

    override suspend fun decline(transfer: String) {
        requests += "decline $transfer"
        offers = offers.filter { it.transfer != transfer }
    }

    override suspend fun cancel(transfer: String) {
        requests += "cancel $transfer"
    }

    override fun events(): Flow<CoreEvent> = events

    companion object {
        fun contact(id: String, name: String, available: Boolean = true, nearby: Boolean = false) = Contact(
            device = id.repeat(32),
            name = name,
            available = available,
            nearby = nearby,
            connected = false,
            route = Route.NONE,
        )

        fun entry(id: Int, name: String, mime: String = "", size: Long = 1000) = Entry(
            id = id.toUInt(),
            parent = 0u,
            directory = false,
            name = name,
            mime = mime,
            size = size.toULong(),
        )

        fun offer(id: String, vararg entries: Entry, resume: UIntArray = UIntArray(0)) = Offer(
            transfer = id.repeat(16),
            from = "a1".repeat(32),
            fromName = "Pixel",
            entries = entries.toList(),
            totalBytes = entries.sumOf { it.size.toLong() }.toULong(),
            resume = resume,
        )

        fun transfer(id: String, state: TransferState, done: Long, total: Long) = Transfer(
            id = id.repeat(16),
            peer = "a1".repeat(32),
            way = Way.INCOMING,
            state = state,
            detail = "",
            bytesDone = done.toULong(),
            bytesTotal = total.toULong(),
        )
    }
}
