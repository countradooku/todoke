// Keeps the process running while a transfer the user started or accepted
// is active (PROTOCOL §10.3: a connectedDevice foreground service started by
// a user action), with an ongoing notification. It stops itself once no
// transfer is moving.

package org.todoke.android.core

import android.app.Notification
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import androidx.core.content.ContextCompat
import androidx.lifecycle.LifecycleService
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import org.todoke.android.R
import org.todoke.android.TodokeApplication
import org.todoke.ffi.TransferState

class TransferService : LifecycleService() {
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        super.onStartCommand(intent, flags, startId)
        val type = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE
        } else {
            0
        }
        ServiceCompat.startForeground(this, NOTIFICATION, notification(0, 0), type)
        // Direct links may be set up while a transfer runs, in the background too.
        (application as TodokeApplication).radios.transferRunning = true
        lifecycleScope.launch { watch() }
        return START_NOT_STICKY
    }

    private suspend fun watch() {
        val backend = (application as TodokeApplication).backendOrNull() ?: return stop()
        while (true) {
            val moving = runCatching { backend.transfers() }.getOrDefault(emptyList())
                .filter { it.state in ACTIVE }
            if (moving.isEmpty()) return stop()
            val done = moving.sumOf { it.bytesDone.toLong() }
            val total = moving.sumOf { it.bytesTotal.toLong() }
            getSystemService(android.app.NotificationManager::class.java)
                .notify(NOTIFICATION, notification(done, total))
            delay(1_000)
        }
    }

    override fun onDestroy() {
        (application as TodokeApplication).radios.transferRunning = false
        super.onDestroy()
    }

    private fun stop() {
        (application as TodokeApplication).radios.transferRunning = false
        ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun notification(done: Long, total: Long): Notification {
        val percent = if (total > 0) (done * 100 / total).toInt() else 0
        return NotificationCompat.Builder(this, Channels.TRANSFERS)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(getString(R.string.transferring))
            .setProgress(100, percent, total == 0L)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .build()
    }

    companion object {
        private const val NOTIFICATION = 1
        private val ACTIVE = setOf(TransferState.ACCEPTED, TransferState.TRANSFERRING, TransferState.OFFERED)

        /** Starts it: call only from a user action (Android 12+ forbids
         * starting it from the background). */
        fun start(context: Context) =
            ContextCompat.startForegroundService(context, Intent(context, TransferService::class.java))
    }
}
