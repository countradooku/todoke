// Every flow of the app against the scripted core, with Compose's
// accessibility checks on (a control without a label, a target too small,
// or text with too little contrast fails the test).

@file:OptIn(ExperimentalUnsignedTypes::class)

package org.todoke.android

import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.accessibility.enableAccessibilityChecks
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.todoke.android.ui.AppRoot
import org.todoke.android.ui.AppViewModel
import org.todoke.android.ui.ARM_DELAY_MS
import org.todoke.android.ui.TodokeTheme
import org.todoke.ffi.Stranger
import org.todoke.ffi.TransferState

@RunWith(AndroidJUnit4::class)
class AppFlowsTest {
    @get:Rule
    val rule = createComposeRule()

    private val fake = FakeBackend()

    private fun text(id: Int, vararg args: Any): String =
        InstrumentationRegistry.getInstrumentation().targetContext.getString(id, *args)

    @Before
    fun accessibility() {
        rule.enableAccessibilityChecks()
    }

    private fun launch() {
        rule.setContent { TodokeTheme { AppRoot(AppViewModel(fake), onTransferStarted = {}) } }
        rule.waitForIdle()
    }

    private fun waitForRequest(prefix: String) =
        rule.waitUntil(5_000) { fake.requests.any { it.startsWith(prefix) } }

    @Test
    fun homeListsDevicesAndOnlyReachableOnesCanBeSentTo() {
        fake.contacts = listOf(
            FakeBackend.contact("a1", "Pixel", available = true, nearby = true),
            FakeBackend.contact("b2", "Laptop", available = false),
        )
        launch()
        rule.waitUntil(5_000) { rule.onAllText("Laptop").isNotEmpty() }
        rule.onNodeWithText("Pixel").assertExists()
        rule.onNodeWithText(text(R.string.route_nearby)).assertExists()
        rule.onNodeWithText(text(R.string.route_away)).assertExists()
    }

    @Test
    fun anOfferIsArmedAfterADelayAndAcceptedWhole() {
        fake.offers = listOf(FakeBackend.offer("e5", FakeBackend.entry(1, "photo.jpg"), FakeBackend.entry(2, "notes.txt")))
        rule.mainClock.autoAdvance = false
        launch()
        rule.mainClock.advanceTimeByFrame()
        rule.waitUntil(5_000) { rule.onAllText(text(R.string.verified_contact)).isNotEmpty() }
        rule.onNodeWithText(text(R.string.accept_all)).assertIsNotEnabled()
        rule.onNodeWithText(text(R.string.decline)).assertIsNotEnabled()
        rule.mainClock.advanceTimeBy(ARM_DELAY_MS + 100)
        rule.onNodeWithText(text(R.string.accept_all)).assertIsEnabled().performClick()
        rule.mainClock.autoAdvance = true
        waitForRequest("accept ${"e5".repeat(16)} ")
        assertTrue(fake.requests.contains("accept ${"e5".repeat(16)} "))
    }

    @Test
    fun choosingSendsOnlyTheChosenFiles() {
        fake.offers = listOf(FakeBackend.offer("e6", FakeBackend.entry(1, "a.txt"), FakeBackend.entry(2, "b.txt")))
        launch()
        rule.waitUntil(5_000) { rule.onAllText(text(R.string.choose)).isNotEmpty() }
        rule.mainClock.advanceTimeBy(ARM_DELAY_MS + 100)
        rule.onNodeWithText(text(R.string.choose)).performClick()
        rule.onNodeWithText(text(R.string.accept_chosen)).assertIsNotEnabled()
        rule.onNodeWithText("b", substring = false).performClick()
        rule.onNodeWithText(text(R.string.accept_chosen)).performClick()
        waitForRequest("accept ${"e6".repeat(16)} 2")
    }

    @Test
    fun declining() {
        fake.offers = listOf(FakeBackend.offer("e7", FakeBackend.entry(1, "a.txt")))
        launch()
        rule.waitUntil(5_000) { rule.onAllText(text(R.string.decline)).isNotEmpty() }
        rule.mainClock.advanceTimeBy(ARM_DELAY_MS + 100)
        rule.onNodeWithText(text(R.string.decline)).performClick()
        waitForRequest("decline ${"e7".repeat(16)}")
    }

    @Test
    fun programsAreFlaggedAndResumedOffersRepeatTheirSelection() {
        fake.offers = listOf(
            FakeBackend.offer("e8", FakeBackend.entry(1, "setup.exe"), FakeBackend.entry(2, "x.txt"), resume = uintArrayOf(1u)),
        )
        launch()
        rule.waitUntil(5_000) { rule.onAllText(text(R.string.programs_warning)).isNotEmpty() }
        rule.onNodeWithText(text(R.string.resumed_offer)).assertExists()
        rule.onNodeWithText(text(R.string.choose)).assertDoesNotExist()
        rule.mainClock.advanceTimeBy(ARM_DELAY_MS + 100)
        rule.onNodeWithText(text(R.string.accept_all)).performClick()
        waitForRequest("accept ${"e8".repeat(16)} 1")
    }

    @Test
    fun pairingShowsTheQrWithoutItsTextAndStopsWhenLeft() {
        launch()
        rule.onNodeWithText(text(R.string.pair_device)).performClick()
        waitForRequest("show-qr")
        rule.onNodeWithContentDescription(text(R.string.qr_secret_label)).assertExists()
        rule.onNodeWithText(text(R.string.done)).performClick()
        waitForRequest("stop-pairing")
    }

    @Test
    fun pairingWithACode() {
        fake.strangers = listOf(Stranger("9f".repeat(8)))
        launch()
        rule.onNodeWithText(text(R.string.pair_device)).performClick()
        rule.onNodeWithText(text(R.string.pair_code)).performClick()
        rule.waitUntil(5_000) { rule.onAllText(text(R.string.nearby_device, "9f9f9f9f")).isNotEmpty() }
        rule.onNodeWithText(text(R.string.nearby_device, "9f9f9f9f")).performClick()
        rule.onNodeWithText(text(R.string.pair)).assertIsNotEnabled()
        rule.onNode(androidx.compose.ui.test.hasSetTextAction()).performTextInput("0123456789")
        rule.onNodeWithText(text(R.string.pair)).performClick()
        waitForRequest("enter-code 0123456789 ${"9f".repeat(8)}")
    }

    @Test
    fun transfersShowProgressAndCanBeCancelled() {
        fake.transfers = listOf(FakeBackend.transfer("f1", TransferState.TRANSFERRING, 500, 1000))
        launch()
        rule.onNodeWithText(text(R.string.nav_transfers)).performClick()
        rule.waitUntil(5_000) { rule.onAllText(text(R.string.cancel)).isNotEmpty() }
        rule.onNodeWithText(text(R.string.cancel)).performClick()
        waitForRequest("cancel ${"f1".repeat(16)}")
    }

    @Test
    fun settingsHideTheDevice() {
        launch()
        rule.onNodeWithText(text(R.string.nav_settings)).performClick()
        rule.onNodeWithText(text(R.string.visibility_hidden)).performClick()
        waitForRequest("hidden true")
    }
}

private fun androidx.compose.ui.test.junit4.ComposeContentTestRule.onAllText(value: String) =
    onAllNodes(androidx.compose.ui.test.hasText(value)).fetchSemanticsNodes()
