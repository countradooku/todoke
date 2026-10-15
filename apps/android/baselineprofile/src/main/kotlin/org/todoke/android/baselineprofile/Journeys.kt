// What a user does first: open the app, then each tab. Shared by the
// profile generator and the benchmark.

package org.todoke.android.baselineprofile

import androidx.benchmark.macro.MacrobenchmarkScope
import androidx.test.uiautomator.By
import androidx.test.uiautomator.Until

const val PACKAGE = "org.todoke.android"

private const val WAIT_MS = 20_000L

/** No permission dialog in the way of the journey. */
fun MacrobenchmarkScope.grantPermissions() {
    device.executeShellCommand("pm grant $PACKAGE android.permission.POST_NOTIFICATIONS")
}

/** Starts the app and waits for Home (its navigation bar), which needs the
 * core: the development libraries (release ones start no core). */
fun MacrobenchmarkScope.start() {
    pressHome()
    startActivityAndWait()
    check(device.wait(Until.hasObject(By.text("Home")), WAIT_MS)) { "Home did not appear" }
}

/** Opens every tab, then Home again. */
fun MacrobenchmarkScope.visitTabs() {
    for (tab in listOf("Transfers", "History", "Settings", "Home")) {
        device.findObject(By.text(tab))?.click() ?: return
        device.waitForIdle()
    }
}
