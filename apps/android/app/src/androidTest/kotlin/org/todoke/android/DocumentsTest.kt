// What another app shares cannot make todoke send its own files: only
// other apps' content URIs are taken from share intents, and an opened
// document inside the app's data is recognised as private, whatever
// path led to it.

package org.todoke.android

import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.ParcelFileDescriptor
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.todoke.android.core.Documents

@RunWith(AndroidJUnit4::class)
class DocumentsTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val scratch = mutableListOf<File>()

    @After
    fun cleanUp() = scratch.forEach { it.delete() }

    private fun file(dir: File?, name: String) = File(dir, name).apply {
        writeText("x")
        scratch += this
    }

    /** An authority one of todoke's own providers answers to. */
    private fun ownAuthority(): String {
        @Suppress("DEPRECATION")
        val providers = context.packageManager.getPackageInfo(context.packageName, PackageManager.GET_PROVIDERS).providers
        return providers!!.first().authority.split(';').first()
    }

    private fun share(vararg uris: Uri) = Intent(Intent.ACTION_SEND_MULTIPLE)
        .putParcelableArrayListExtra(Intent.EXTRA_STREAM, ArrayList(uris.toList()))

    @Test
    fun onlyOtherAppsContentUrisAreShareable() {
        val key = File(context.noBackupFilesDir, "keys/profile.key")
        assertFalse(Documents.shareable(context, Uri.fromFile(key)))
        assertFalse(Documents.shareable(context, Uri.parse("content://${ownAuthority()}/anything")))
        assertFalse(Documents.shareable(context, Uri.parse("content://no.such.provider/x")))
        assertTrue(Documents.shareable(context, Uri.parse("content://settings/system")))
    }

    @Test
    fun aShareOfOnlyPrivateUrisIsDropped() {
        val own = Uri.fromFile(File(context.filesDir, "todoke/storage.id"))
        assertNull(SharedFiles.from(context, share(own, Uri.parse("content://${ownAuthority()}/x"))))
        val mixed = SharedFiles.from(context, share(own, Uri.parse("content://settings/system")))
        assertEquals(listOf(Uri.parse("content://settings/system")), mixed?.uris)
    }

    @Test
    fun openFilesInsideTheAppDataArePrivate() {
        for (dir in listOf(context.filesDir, context.noBackupFilesDir, context.cacheDir)) {
            ParcelFileDescriptor.open(file(dir, "private.txt"), ParcelFileDescriptor.MODE_READ_ONLY).use {
                assertTrue(dir.path, Documents.isPrivate(context, it))
            }
        }
        // Opened through the other name of the data directory.
        val aliased = File("/data/data/${context.packageName}/files/${file(context.filesDir, "aliased.txt").name}")
        ParcelFileDescriptor.open(aliased, ParcelFileDescriptor.MODE_READ_ONLY).use {
            assertTrue(Documents.isPrivate(context, it))
        }
    }

    @Test
    fun filesOutsideTheAppDataAreNot() {
        ParcelFileDescriptor.open(file(context.getExternalFilesDir(null), "shared.txt"), ParcelFileDescriptor.MODE_READ_ONLY).use {
            assertFalse(Documents.isPrivate(context, it))
        }
    }
}
