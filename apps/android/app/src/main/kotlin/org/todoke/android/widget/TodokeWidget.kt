// A home-screen widget: whether the device is visible to contacts, and a
// way into the app. It shows nothing about contacts or files.

package org.todoke.android.widget

import android.content.Context
import androidx.compose.ui.unit.dp
import androidx.glance.GlanceId
import androidx.glance.GlanceModifier
import androidx.glance.action.actionStartActivity
import androidx.glance.action.clickable
import androidx.glance.appwidget.GlanceAppWidget
import androidx.glance.appwidget.GlanceAppWidgetReceiver
import androidx.glance.appwidget.provideContent
import androidx.glance.background
import androidx.glance.layout.Column
import androidx.glance.layout.padding
import androidx.glance.text.Text
import androidx.glance.GlanceTheme
import org.todoke.android.MainActivity
import org.todoke.android.R
import org.todoke.android.TodokeApplication

class TodokeWidget : GlanceAppWidget() {
    override suspend fun provideGlance(context: Context, id: GlanceId) {
        val hidden = (context.applicationContext as TodokeApplication).prefs.hidden
        provideContent {
            GlanceTheme {
                Column(
                    GlanceModifier.background(GlanceTheme.colors.widgetBackground).padding(12.dp)
                        .clickable(actionStartActivity<MainActivity>()),
                ) {
                    Text(context.getString(R.string.app_name))
                    Text(context.getString(if (hidden) R.string.visibility_hidden else R.string.visibility_contacts))
                }
            }
        }
    }
}

class TodokeWidgetReceiver : GlanceAppWidgetReceiver() {
    override val glanceAppWidget: GlanceAppWidget = TodokeWidget()
}
