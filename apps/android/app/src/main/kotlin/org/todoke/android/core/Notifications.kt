// The core's notifications on Android: offers (sender and counts, never a
// file name), offers gone, and endings. A notification only opens the app;
// accepting happens there (PROTOCOL §7.2: the user's decision, seeing the
// offer).

package org.todoke.android.core

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import org.todoke.android.MainActivity
import org.todoke.android.R
import org.todoke.ffi.Notifier
import org.todoke.ffi.OfferNotice

object Channels {
    const val OFFERS = "offers"
    const val TRANSFERS = "transfers"
    const val DONE = "done"

    fun create(context: Context) {
        val manager = context.getSystemService(NotificationManager::class.java)
        manager.createNotificationChannels(
            listOf(
                NotificationChannel(OFFERS, context.getString(R.string.channel_offers), NotificationManager.IMPORTANCE_HIGH),
                NotificationChannel(TRANSFERS, context.getString(R.string.channel_transfers), NotificationManager.IMPORTANCE_LOW),
                NotificationChannel(DONE, context.getString(R.string.channel_done), NotificationManager.IMPORTANCE_DEFAULT),
            ),
        )
    }
}

class TodokeNotifier(private val context: Context) : Notifier {
    private val manager = NotificationManagerCompat.from(context)

    private fun allowed(): Boolean =
        ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) ==
            PackageManager.PERMISSION_GRANTED

    private fun open(): PendingIntent = PendingIntent.getActivity(
        context,
        0,
        Intent(context, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
        PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
    )

    private fun id(transfer: String) = transfer.hashCode()

    override fun offerReceived(notice: OfferNotice) {
        if (!allowed()) return
        val text = context.resources.getQuantityString(R.plurals.offer_counts, notice.files.toInt(), notice.files.toInt())
        val notification = NotificationCompat.Builder(context, Channels.OFFERS)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(context.getString(R.string.offer_from, notice.fromName))
            .setContentText(text)
            .setCategory(NotificationCompat.CATEGORY_MESSAGE)
            .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
            .setContentIntent(open())
            .setAutoCancel(true)
            .build()
        try {
            manager.notify(id(notice.transfer), notification)
        } catch (_: SecurityException) {
        }
    }

    override fun offerGone(transfer: String) = manager.cancel(id(transfer))

    override fun transferFinished(transfer: String, text: String) {
        if (!allowed()) return
        val notification = NotificationCompat.Builder(context, Channels.DONE)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(context.getString(R.string.app_name))
            .setContentText(text)
            .setContentIntent(open())
            .setAutoCancel(true)
            .build()
        try {
            manager.notify(id(transfer), notification)
        } catch (_: SecurityException) {
        }
    }

    override fun missed() {
        // Events were lost: drop every offer notification; the app shows the
        // offers waiting when opened.
        manager.cancelAll()
    }
}
