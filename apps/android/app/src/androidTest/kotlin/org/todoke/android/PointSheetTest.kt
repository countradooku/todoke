// The Point sheet: shown, it points with the controllers the platform
// prepared; closed, pointing stops even though the sheet's own scope is
// gone by then.

package org.todoke.android

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableStateFlow
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.todoke.android.radio.Pointing
import org.todoke.android.ui.PointSheet
import org.todoke.android.ui.TodokeTheme

@RunWith(AndroidJUnit4::class)
class PointSheetTest {
    @get:Rule
    val rule = createComposeRule()

    private fun FakeBackend.waitFor(request: String) =
        rule.waitUntil(5_000) { request in requests }

    @Test
    fun closingTheSheetStopsPointing() {
        val backend = FakeBackend()
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        try {
            val pointing = Pointing(backend, FakeUwb(), MutableStateFlow(true), { true }, scope)
            backend.waitFor("ranging-ready true")
            var shown by mutableStateOf(true)
            rule.setContent {
                TodokeTheme {
                    if (shown) PointSheet(pointing, backend.contacts, onChoose = {}, onDismiss = { shown = false })
                }
            }
            backend.waitFor("point-start [${0x1111}]")
            shown = false
            backend.waitFor("point-stop")
        } finally {
            scope.cancel()
        }
    }
}
