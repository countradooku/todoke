// The Backend on the real core (the BoltFFI bindings), held through
// Guarded so it is freed only after every call on it has finished. Calls
// block in the core: they run on Dispatchers.IO.

@file:OptIn(ExperimentalUnsignedTypes::class)

package org.todoke.android.core

import android.content.ContentResolver
import android.os.ParcelFileDescriptor
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.withContext
import org.todoke.ffi.Contact
import org.todoke.ffi.Core
import org.todoke.ffi.CoreEvent
import org.todoke.ffi.Guarded
import org.todoke.ffi.HistoryItem
import org.todoke.ffi.Offer
import org.todoke.ffi.Status
import org.todoke.ffi.Stranger
import org.todoke.ffi.Transfer
import org.todoke.ffi.events

class CoreBackend(private val core: Guarded<Core>, private val resolver: ContentResolver) : Backend {
    private suspend fun <R> call(block: (Core) -> R): R = withContext(Dispatchers.IO) { core.call(block) }

    override suspend fun status(): Status = call { it.status() }

    override suspend fun contacts(): List<Contact> = call { it.contacts() }

    override suspend fun transfers(): List<Transfer> = call { it.transfers() }

    override suspend fun offers(): List<Offer> = call { it.offers() }

    override suspend fun history(): List<HistoryItem> = call { it.history() }

    override suspend fun clearHistory() = call { it.clearHistory() }

    override suspend fun showQr(): QrCode = call { core ->
        core.pairShowQr().use { offer ->
            val width = offer.width().toInt()
            val modules = offer.modules()
            QrCode(width, BooleanArray(width * width) { modules[it] != 0.toByte() }, offer.expiresAt().toLong())
        }
    }

    override suspend fun scanQr(text: String): String = call { core -> core.pairScanQr(text).use { it.device() } }

    override suspend fun showCode(): PairingCode = call { core ->
        core.pairShowCode().use { PairingCode(it.code(), it.expiresAt().toLong()) }
    }

    override suspend fun strangers(): List<Stranger> = call { it.strangers() }

    override suspend fun enterCode(code: String, stranger: String): String =
        call { core -> core.pairEnterCode(code, stranger).use { it.device() } }

    override suspend fun stopPairing() = call { it.stopPairing() }

    override suspend fun setHidden(hidden: Boolean) = call { it.setHidden(hidden) }

    override suspend fun send(contact: String, documents: List<Picked>): String = withContext(Dispatchers.IO) {
        val opened = mutableListOf<ParcelFileDescriptor>()
        try {
            for (document in documents) {
                opened += resolver.openFileDescriptor(document.uri, "r")
                    ?: throw java.io.FileNotFoundException("a picked document could not be opened")
            }
            core.call { core ->
                core.contact(contact).use { handle ->
                    // Handed over now: the core owns and closes them, whatever
                    // sendFiles returns.
                    val fds = opened.map { it.detachFd() }
                    opened.clear()
                    handle.sendFiles(documents.map { it.name }, fds.toIntArray()).use { it.id() }
                }
            }
        } finally {
            opened.forEach { it.close() }
        }
    }

    override suspend fun accept(transfer: String, files: List<UInt>) =
        call { core -> core.transfer(transfer).use { it.accept(files.toUIntArray()) } }

    override suspend fun decline(transfer: String) = call { core -> core.transfer(transfer).use { it.decline() } }

    override suspend fun cancel(transfer: String) = call { core -> core.transfer(transfer).use { it.cancel() } }

    override fun events(): Flow<CoreEvent> = core.events()
}
