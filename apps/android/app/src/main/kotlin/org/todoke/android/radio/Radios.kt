// When the app may use its radios: while one of its screens is in the
// foreground, or while a transfer runs (in the foreground service). Links
// exist only for transfers and pointing only on screen, so nothing scans or
// advertises in the background otherwise.

package org.todoke.android.radio

import android.app.Activity
import android.app.Application
import android.os.Bundle
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

class Radios(application: Application) {
    private val _foreground = MutableStateFlow(false)

    /** Whether one of the app's screens is started. */
    val foreground: StateFlow<Boolean> get() = _foreground

    /** Set by the transfer service while it runs. */
    @Volatile
    var transferRunning = false

    fun active(): Boolean = _foreground.value || transferRunning

    init {
        application.registerActivityLifecycleCallbacks(
            object : Application.ActivityLifecycleCallbacks {
                private var started = 0

                override fun onActivityStarted(activity: Activity) {
                    started += 1
                    _foreground.value = true
                }

                override fun onActivityStopped(activity: Activity) {
                    started = (started - 1).coerceAtLeast(0)
                    _foreground.value = started > 0
                }

                override fun onActivityCreated(activity: Activity, state: Bundle?) {}

                override fun onActivityResumed(activity: Activity) {}

                override fun onActivityPaused(activity: Activity) {}

                override fun onActivitySaveInstanceState(activity: Activity, state: Bundle) {}

                override fun onActivityDestroyed(activity: Activity) {}
            },
        )
    }
}
