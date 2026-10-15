// Resumes interrupted transfers in the background when the network is back
// (WorkManager): starts the core if it can start without the user (a gated
// key needs an unlock, so then it waits for the app to be opened), and keeps
// it running while a transfer is moving, within WorkManager's time limit.

package org.todoke.android.core

import android.content.Context
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.delay
import org.todoke.android.TodokeApplication
import org.todoke.ffi.TransferState

class ResumeWorker(context: Context, parameters: WorkerParameters) : CoroutineWorker(context, parameters) {
    override suspend fun doWork(): Result {
        val app = applicationContext as TodokeApplication
        if (app.prefs.gate && app.backendOrNull() == null) return Result.success()
        app.start()
        val backend = app.backendOrNull() ?: return Result.success()
        // The core reconnects and resumes on its own; give it the time.
        repeat(MAX_CHECKS) {
            delay(CHECK_MS)
            val moving = runCatching { backend.transfers() }.getOrDefault(emptyList())
                .any { it.state == TransferState.TRANSFERRING || it.state == TransferState.INTERRUPTED }
            if (!moving) return Result.success()
        }
        return Result.success()
    }

    companion object {
        private const val CHECK_MS = 10_000L
        private const val MAX_CHECKS = 50

        fun schedule(context: Context) {
            val request = PeriodicWorkRequestBuilder<ResumeWorker>(15, TimeUnit.MINUTES)
                .setConstraints(Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build())
                .build()
            WorkManager.getInstance(context)
                .enqueueUniquePeriodicWork("resume", ExistingPeriodicWorkPolicy.KEEP, request)
        }
    }
}
