// Moving received files out of app storage: published files and folders
// move, staged files and links stay, nothing is overwritten, a failed copy
// is removed there and kept here, and nothing moves while a file is being
// received. The folder is a plain directory standing in for a document
// tree (a provider picks a free name the same way).

package org.todoke.android

import android.os.Build
import android.system.Os
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import java.io.IOException
import java.io.InputStream
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.todoke.android.core.Exporter
import org.todoke.android.core.Folder
import org.todoke.android.core.NewFile
import org.todoke.ffi.TransferState

@RunWith(AndroidJUnit4::class)
class ExporterTest {
    private val scratch = File(InstrumentationRegistry.getInstrumentation().targetContext.cacheDir, "exporter-test")
    private val received = File(scratch, "received").apply { mkdirs() }
    private val chosen = File(scratch, "chosen").apply { mkdirs() }
    private val backend = FakeBackend()

    @After
    fun cleanUp() {
        scratch.deleteRecursively()
    }

    /** A directory as the chosen folder; with `failing`, writing that name
     * fails halfway with that error; `writing` runs before each write. */
    private class DirFolder(
        private val dir: File,
        private val failing: String? = null,
        private val error: () -> Exception = { IOException("the provider went away") },
        private val writing: (String) -> Unit = {},
    ) : Folder {
        override fun createFile(name: String, mime: String): NewFile {
            val file = free(name).apply { createNewFile() }
            return object : NewFile {
                override fun write(content: InputStream) {
                    writing(name)
                    file.outputStream().use { out ->
                        if (name == failing) {
                            out.write(content.read())
                            throw error()
                        }
                        content.copyTo(out)
                    }
                }

                override fun delete() {
                    file.delete()
                }
            }
        }

        override fun createFolder(name: String): Folder = DirFolder(free(name).apply { mkdir() }, failing, error, writing)

        /** `name`, or `name (1)`, `name (2)`…: what the external storage provider does. */
        private fun free(name: String): File =
            generateSequence(0) { it + 1 }.map { if (it == 0) File(dir, name) else File(dir, "$name ($it)") }.first { !it.exists() }
    }

    private fun write(path: String, text: String) = File(received, path).apply {
        parentFile?.mkdirs()
        writeText(text)
    }

    @Test
    fun publishedFilesAndFoldersMove() = runBlocking {
        write("report.pdf", "pdf")
        write("photos/IMG_1.jpg", "one")
        write("photos/trip/IMG_2.jpg", "two")
        File(chosen, "report.pdf").writeText("already there")

        assertEquals(3, Exporter(received).exportWhenQuiet(backend, DirFolder(chosen)))

        assertEquals("already there", File(chosen, "report.pdf").readText())
        assertEquals("pdf", File(chosen, "report.pdf (1)").readText())
        assertEquals("one", File(chosen, "photos/IMG_1.jpg").readText())
        assertEquals("two", File(chosen, "photos/trip/IMG_2.jpg").readText())
        assertEquals(emptyList<String>(), received.list()!!.toList())
    }

    @Test
    fun stagedFilesAndLinksStay() = runBlocking {
        write(".todoke-0123456789abcdef.part", "partial")
        write("folder/.TODOKE-feed.part", "partial")
        write("kept.txt", "kept")
        Os.symlink(File(received, "kept.txt").path, File(received, "link.txt").path)

        assertEquals(1, Exporter(received).exportWhenQuiet(backend, DirFolder(chosen)))

        assertEquals(listOf(".todoke-0123456789abcdef.part", "folder", "link.txt"), received.list()!!.sorted())
        assertTrue(File(received, "folder/.TODOKE-feed.part").exists())
        assertEquals(listOf("kept.txt"), chosen.list()!!.toList())
    }

    @Test
    fun aFailedCopyIsRemovedThereAndKeptHere() {
        write("a.txt", "first")
        write("b.txt", "second")
        val exporter = Exporter(received)

        assertThrows(IOException::class.java) {
            runBlocking { exporter.exportWhenQuiet(backend, DirFolder(chosen, failing = "b.txt")) }
        }

        assertEquals(listOf("a.txt"), chosen.list()!!.toList())
        assertEquals("second", File(received, "b.txt").readText())
        assertFalse(File(received, "a.txt").exists())
    }

    @Test
    fun nothingMovesWhileAFileIsBeingReceived() = runBlocking {
        write("done.txt", "done")
        val exporter = Exporter(received)
        for (state in listOf(TransferState.ACCEPTED, TransferState.TRANSFERRING)) {
            backend.transfers = listOf(FakeBackend.transfer("t1", state, 1, 2))
            assertEquals(0, exporter.exportWhenQuiet(backend, DirFolder(chosen)))
        }
        assertTrue(File(received, "done.txt").exists())

        // Interrupted: it may resume, and before Android 11 publication is
        // a copy, so the export waits it out there.
        backend.transfers = listOf(FakeBackend.transfer("t2", TransferState.INTERRUPTED, 1, 2))
        val copies = Build.VERSION.SDK_INT < Build.VERSION_CODES.R
        assertEquals(if (copies) 0 else 1, exporter.exportWhenQuiet(backend, DirFolder(chosen)))

        // Waiting for a decision: nothing is being written.
        backend.transfers = listOf(FakeBackend.transfer("t1", TransferState.AWAITING_DECISION, 0, 2))
        assertEquals(if (copies) 1 else 0, exporter.exportWhenQuiet(backend, DirFolder(chosen)))
        assertFalse(File(received, "done.txt").exists())
    }

    @Test
    fun aRevokedGrantLeavesNoPartialCopy() {
        write("a.txt", "kept")
        val revoked = DirFolder(chosen, failing = "a.txt", error = { SecurityException("the grant was revoked") })
        assertThrows(SecurityException::class.java) { runBlocking { Exporter(received).exportWhenQuiet(backend, revoked) } }
        assertEquals(emptyList<String>(), chosen.list()!!.toList())
        assertEquals("kept", File(received, "a.txt").readText())
    }

    /** An offer accepted while a file moves waits for that file, and the
     * export stops before the next one. */
    @Test
    fun anAcceptWaitsForTheFileInHandAndStopsTheExport() = runBlocking {
        write("a.txt", "first")
        write("b.txt", "second")
        val exporter = Exporter(received)
        var lockedDuringWrite = false
        val folder = DirFolder(chosen, writing = { name ->
            if (name == "a.txt") {
                lockedDuringWrite = exporter.receiving.isLocked
                // The user accepts an offer now.
                backend.transfers = listOf(FakeBackend.transfer("t1", TransferState.ACCEPTED, 0, 2))
            }
        })
        assertEquals(1, exporter.exportWhenQuiet(backend, folder))
        assertTrue(lockedDuringWrite)
        assertEquals(listOf("a.txt"), chosen.list()!!.toList())
        assertEquals("second", File(received, "b.txt").readText())
    }
}
