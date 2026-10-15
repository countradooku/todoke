// Received files leave app-private storage, where the core receives and
// publishes them (the quarantine), for the folder the user chose: a Storage
// Access Framework tree. Only at a quiet moment, when nothing is being
// received: before Android 11 the core publishes by copying, so a file is
// visible under its name before it is whole. Accepting an offer waits for
// the file being moved, and every file is checked again before it moves. Staged files (names starting
// `.todoke-`, which the core never gives a received file) and links are
// left alone. Document providers never overwrite: they pick a free name. A
// file here is deleted only after its copy there was written and closed; a
// copy that fails is deleted there and the file stays here.

package org.todoke.android.core

import android.content.ContentResolver
import android.net.Uri
import android.os.Build
import android.os.ParcelFileDescriptor
import android.provider.DocumentsContract
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import android.webkit.MimeTypeMap
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.io.SyncFailedException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.todoke.ffi.TransferState
import org.todoke.ffi.Way

/** A folder files are exported into. */
interface Folder {
    /** A new, empty file named `name` or, if that is taken, a name the
     * folder picks. */
    fun createFile(name: String, mime: String): NewFile

    /** A new folder named `name`, or a name the folder picks. */
    fun createFolder(name: String): Folder
}

/** A file just created in a [Folder]. */
interface NewFile {
    /** Writes `content` and makes it durable where the folder can. */
    fun write(content: InputStream)

    fun delete()
}

/** A folder in a document tree the user granted (`OpenDocumentTree`). */
class SafFolder(private val resolver: ContentResolver, private val document: Uri) : Folder {
    override fun createFile(name: String, mime: String): NewFile = SafFile(resolver, create(mime, name))

    override fun createFolder(name: String): Folder = SafFolder(resolver, create(DocumentsContract.Document.MIME_TYPE_DIR, name))

    private fun create(mime: String, name: String): Uri =
        DocumentsContract.createDocument(resolver, document, mime, name)
            ?: throw IOException("the folder refused a new document")

    companion object {
        /** The top of the tree `tree`. */
        fun tree(resolver: ContentResolver, tree: Uri) =
            SafFolder(resolver, DocumentsContract.buildDocumentUriUsingTree(tree, DocumentsContract.getTreeDocumentId(tree)))
    }
}

private class SafFile(private val resolver: ContentResolver, private val document: Uri) : NewFile {
    override fun write(content: InputStream) {
        val descriptor = resolver.openFileDescriptor(document, "w")
            ?: throw IOException("the new document could not be opened")
        ParcelFileDescriptor.AutoCloseOutputStream(descriptor).use { out ->
            content.copyTo(out, BUFFER)
            out.flush()
            try {
                descriptor.fileDescriptor.sync()
            } catch (_: SyncFailedException) {
                // A provider that streams through a pipe cannot sync.
            }
        }
    }

    override fun delete() {
        DocumentsContract.deleteDocument(resolver, document)
    }

    private companion object {
        const val BUFFER = 1 shl 16
    }
}

/** Moves what the core published in `received` into a [Folder]. */
class Exporter(private val received: File) {
    /**
     * Held while one file moves, and by [CoreBackend.accept]: an offer
     * accepted while the export runs waits for the file in hand, and the
     * next file sees the transfer and stops the export.
     */
    val receiving = Mutex()

    /** One export at a time (two would copy the same file twice). */
    private val exports = Mutex()

    /**
     * Moves everything published in `received` into `into`, file by file,
     * each only while no incoming transfer is accepted or moving (before
     * Android 11, where publication is a copy, nor interrupted). The next
     * transfer to end calls this again. Returns how many files moved.
     */
    suspend fun exportWhenQuiet(backend: Backend, into: Folder): Int = exports.withLock {
        withContext(Dispatchers.IO) { move(backend, received, lazy { into }) }
    }

    /** `into` is made only when something moves into it: a folder holding
     * only staged files leaves nothing there. */
    private suspend fun move(backend: Backend, dir: File, into: Lazy<Folder>): Int {
        var moved = 0
        for (entry in dir.listFiles().orEmpty().sortedBy { it.name }) {
            if (entry.name.startsWith(TEMP_PREFIX, ignoreCase = true)) continue
            val mode = try {
                Os.lstat(entry.path).st_mode
            } catch (_: ErrnoException) {
                continue
            }
            when {
                OsConstants.S_ISREG(mode) -> {
                    if (!receiving.withLock { quiet(backend) && moveFile(entry, into) }) return moved
                    moved++
                }
                OsConstants.S_ISDIR(mode) -> {
                    moved += move(backend, entry, lazy { into.value.createFolder(entry.name) })
                    // Only once empty: anything left behind stays here.
                    entry.delete()
                }
            }
        }
        return moved
    }

    private suspend fun quiet(backend: Backend): Boolean {
        val busy = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) RECEIVING else RECEIVING_BY_COPY
        return backend.transfers().none { it.way == Way.INCOMING && it.state in busy }
    }

    /** Copies `entry` there, then removes it here; false (and nothing
     * removed here) if it changed while it was copied. */
    private fun moveFile(entry: File, into: Lazy<Folder>): Boolean {
        val before = Os.lstat(entry.path)
        val copy = into.value.createFile(entry.name, mime(entry.name))
        try {
            entry.inputStream().use(copy::write)
        } catch (error: Exception) {
            runCatching { copy.delete() }
            throw error
        }
        val after = Os.lstat(entry.path)
        if (after.st_size != before.st_size || after.st_mtime != before.st_mtime || after.st_ino != before.st_ino) {
            runCatching { copy.delete() }
            return false
        }
        if (!entry.delete()) throw IOException("an exported file could not be removed here")
        return true
    }

    companion object {
        /** What the core names a file it is still writing. */
        const val TEMP_PREFIX = ".todoke-"

        private val RECEIVING = setOf(TransferState.ACCEPTED, TransferState.TRANSFERRING)

        /** Before Android 11 an interrupted transfer may resume and publish
         * by copying: wait for it to end. */
        private val RECEIVING_BY_COPY = RECEIVING + TransferState.INTERRUPTED

        fun mime(name: String): String =
            name.substringAfterLast('.', "").lowercase().takeIf { it.isNotEmpty() }
                ?.let { MimeTypeMap.getSingleton().getMimeTypeFromExtension(it) }
                ?: "application/octet-stream"
    }
}
