// Documents handed to todoke are untrusted: a share intent from any app
// can name any URI, and todoke opens it with its own rights, so a URI that
// points at todoke's own files (its wrapped key, its sealed state) would be
// sent away for that app. Only content URIs of other apps' providers are
// taken from share intents, and whatever is opened, shared or picked, is
// refused when the open descriptor is one of the app's own files (checked
// on the descriptor, so no path trick or provider gets around it).

package org.todoke.android.core

import android.content.ContentResolver
import android.content.Context
import android.net.Uri
import android.os.ParcelFileDescriptor
import android.system.ErrnoException
import android.system.Os
import androidx.core.content.ContextCompat
import java.io.File

object Documents {
    /** Whether a URI another app shared may be opened at all. */
    fun shareable(context: Context, uri: Uri): Boolean {
        if (uri.scheme != ContentResolver.SCHEME_CONTENT) return false
        val authority = uri.authority ?: return false
        val provider = context.packageManager.resolveContentProvider(authority, 0) ?: return false
        return provider.packageName != context.packageName
    }

    /** Whether `descriptor` is one of this app's own files (or cannot be
     * told apart from one). */
    fun isPrivate(context: Context, descriptor: ParcelFileDescriptor): Boolean {
        val path = try {
            Os.readlink("/proc/self/fd/${descriptor.fd}")
        } catch (_: ErrnoException) {
            return true
        }
        return roots(context).any { root -> path == root || path.startsWith("$root/") }
    }

    /** The app's data directories, under every name the kernel may report. */
    private fun roots(context: Context): Set<String> {
        val dirs = listOfNotNull(
            File(context.applicationInfo.dataDir),
            ContextCompat.getDataDir(context),
            context.createDeviceProtectedStorageContext().filesDir.parentFile,
            File("/data/data/${context.packageName}"),
        )
        return dirs.flatMap { listOf(it.path, runCatching { it.canonicalPath }.getOrDefault(it.path)) }.toSet()
    }
}
