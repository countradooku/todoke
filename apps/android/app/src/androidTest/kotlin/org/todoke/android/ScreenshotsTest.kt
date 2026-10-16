// Screenshots of every screen, light and dark, against the scripted core:
// written to the test's additional output, which the connected test task
// copies to app/build/outputs/connected_android_test_additional_output.
// Screens with a bottom sheet are taken from the whole display; the pairing
// screens from the composable itself (their window is FLAG_SECURE, which a
// display screenshot shows black).

@file:OptIn(ExperimentalUnsignedTypes::class)

package org.todoke.android

import android.graphics.Bitmap
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.Surface
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asAndroidBitmap
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.captureToImage
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.todoke.android.ui.AppRoot
import org.todoke.android.ui.AppViewModel
import org.todoke.android.ui.Destination
import org.todoke.android.ui.ShareSheet
import org.todoke.android.ui.TodokeTheme
import org.todoke.ffi.HistoryItem
import org.todoke.ffi.Stranger
import org.todoke.ffi.TransferState
import org.todoke.ffi.Way

@RunWith(AndroidJUnit4::class)
class ScreenshotsTest {
    @get:Rule
    val rule = createComposeRule()

    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext
    private var dark by mutableStateOf(false)

    private val fake = FakeBackend().apply {
        contacts = listOf(
            FakeBackend.contact("a1", "Pixel 9", available = true, nearby = true),
            FakeBackend.contact("b2", "MacBook", available = true, nearby = true),
            FakeBackend.contact("c3", "Office PC", available = false),
        )
        transfers = listOf(
            FakeBackend.transfer("f1", TransferState.TRANSFERRING, 412_000_000, 1_048_000_000),
            FakeBackend.transfer("f2", TransferState.DELIVERED, 3_200_000, 3_200_000),
        )
        history = listOf(
            HistoryItem(
                transfer = "h1".repeat(16), peer = "a1".repeat(32), way = Way.INCOMING,
                state = TransferState.RECEIVED, detail = "", finishedAt = 1_790_000_000u, files = 12u,
                bytes = 48_000_000u, names = listOf("Holiday photos", "itinerary.pdf"),
                manifestHash = "9c2f".repeat(16), receipt = "7a".repeat(16),
            ),
            HistoryItem(
                transfer = "h2".repeat(16), peer = "b2".repeat(32), way = Way.OUTGOING,
                state = TransferState.DELIVERED, detail = "", finishedAt = 1_789_900_000u, files = 1u,
                bytes = 2_400_000u, names = listOf("report.docx"), manifestHash = "1d4e".repeat(16),
                receipt = "3b".repeat(16),
            ),
        )
        strangers = listOf(Stranger("9f".repeat(8)))
    }

    private fun save(name: String, bitmap: Bitmap) {
        // The runner names the directory; the app's own files go when the
        // test run uninstalls it.
        // The connected test task copies this directory back; releases that
        // get none keep the screenshots in the app's external files.
        val output = InstrumentationRegistry.getArguments().getString("additionalTestOutputDir")
            ?: context.getExternalFilesDir(null)?.path ?: return
        val dir = File(output, "screenshots").apply { mkdirs() }
        File(dir, "$name-${if (dark) "dark" else "light"}.png").outputStream().use {
            bitmap.compress(Bitmap.CompressFormat.PNG, 100, it)
        }
    }

    private fun display(): Bitmap = instrumentation.uiAutomation.takeScreenshot()

    private fun composable(): Bitmap = rule.onRoot().captureToImage().asAndroidBitmap()

    /** Shows the app at `start`, then takes `name` in both themes. */
    private fun shoot(name: String, start: Destination = Destination.Home, pairing: Int? = null,
                      prepare: () -> Unit = {}, take: () -> Bitmap = ::display) {
        rule.setContent {
            TodokeTheme(dark = dark) {
                Surface(Modifier.fillMaxSize()) {
                    AppRoot(AppViewModel(fake), onTransferStarted = {}, start = start, startPairing = pairing)
                }
            }
        }
        if (start == Destination.Home && pairing == null) {
            rule.waitUntil(5_000) { rule.onAllNodes(androidx.compose.ui.test.hasText("Pixel 9")).fetchSemanticsNodes().isNotEmpty() }
        }
        prepare()
        settle()
        save(name, take())
        dark = true
        settle()
        save(name, take())
    }

    private fun settle() {
        rule.waitForIdle()
        rule.mainClock.advanceTimeBy(1_500)
        rule.waitForIdle()
        Thread.sleep(500)
    }

    @Test fun home() = shoot("1-home")

    @Test fun transfers() = shoot("3-transfers", start = Destination.Transfers)

    @Test fun history() = shoot("4-history", start = Destination.History)

    @Test fun settings() = shoot("5-settings", start = Destination.Settings)

    @Test fun receive() {
        fake.offers = listOf(
            FakeBackend.offer(
                "e5",
                FakeBackend.entry(1, "IMG_2041.jpg", "image/jpeg", 4_200_000),
                FakeBackend.entry(2, "IMG_2042.jpg", "image/jpeg", 3_900_000),
                FakeBackend.entry(3, "trip-notes.pdf", "application/pdf", 210_000),
                FakeBackend.entry(4, "setup.exe", "application/x-msdownload", 12_000_000),
            ),
        )
        shoot("2-receive")
    }

    @Test fun pairQr() = shoot("6-pair-qr", pairing = 0, take = ::composable)

    @Test fun pairScan() = shoot("7-pair-scan", pairing = 1, take = ::composable)

    @Test fun pairCode() = shoot(
        "8-pair-code",
        pairing = 2,
        prepare = {
            rule.onNodeWithText(context.getString(R.string.show_code)).performClick()
            rule.waitUntil(5_000) { rule.onAllNodes(androidx.compose.ui.test.hasText("01234 56789")).fetchSemanticsNodes().isNotEmpty() }
        },
        take = ::composable,
    )

    @Test fun share() {
        rule.setContent {
            // Over the app, as MainActivity shows files shared into it.
            TodokeTheme(dark = dark) {
                Surface(Modifier.fillMaxSize()) {
                    AppRoot(AppViewModel(fake), onTransferStarted = {})
                    ShareSheet(fake.contacts, names = listOf("IMG_2041.jpg", "IMG_2042.jpg", "trip-notes.pdf"), preselected = "a1".repeat(32), onSend = {}, onDismiss = {})
                }
            }
        }
        settle()
        save("9-share", display())
        dark = true
        settle()
        save("9-share", display())
    }
}
