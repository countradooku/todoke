// Screenshots of every screen in light and dark, against the scripted core,
// kept as attachments of the test results (exported with `xcrun
// xcresulttool export attachments`).

import XCTest

final class ScreenshotsTests: XCTestCase {
    private func shoot(_ name: String, scenario: String, steps: (XCUIApplication) -> Void = { _ in }) {
        for (appearance, suffix) in [(XCUIDevice.Appearance.light, "light"), (.dark, "dark")] {
            XCUIDevice.shared.appearance = appearance
            let app = XCUIApplication()
            app.launchArguments = ["-ui-test-scenario", scenario]
            app.launch()
            steps(app)
            // Animations and the receive sheet's arming settle first.
            Thread.sleep(forTimeInterval: 1.5)
            let shot = XCTAttachment(screenshot: XCUIScreen.main.screenshot())
            shot.name = "\(name)-\(suffix)"
            shot.lifetime = .keepAlways
            add(shot)
            app.terminate()
        }
    }

    func testHome() { shoot("1-home", scenario: "default") }

    func testReceive() { shoot("2-receive", scenario: "offer") }

    func testTransfers() {
        shoot("3-transfers", scenario: "transfers") { $0.tabBars.buttons["Transfers"].tap() }
    }

    func testHistory() {
        shoot("4-history", scenario: "history") { $0.tabBars.buttons["History"].tap() }
    }

    func testSettings() {
        shoot("5-settings", scenario: "default") { $0.tabBars.buttons["Settings"].tap() }
    }

    func testPairQr() {
        shoot("6-pair-qr", scenario: "default") { $0.buttons["pair"].tap() }
    }

    func testPairCode() {
        shoot("7-pair-code", scenario: "strangers") { app in
            app.buttons["pair"].tap()
            app.segmentedControls["pair-method"].buttons["Code"].tap()
            app.buttons["show-code"].tap()
        }
    }

    func testEmpty() { shoot("8-empty", scenario: "empty") }
}
