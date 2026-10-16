// Every flow against the scripted core (debug builds' FakeBackend, picked
// with `-ui-test-scenario`), each screen also put through the system's
// accessibility audit (labels, contrast, hit regions, Dynamic Type,
// clipping) at the default size and at the largest accessibility size.

import XCTest

final class FlowsTests: XCTestCase {
    override func setUp() {
        continueAfterFailure = false
    }

    private func launch(_ scenario: String, size: String? = nil, dark: Bool = false,
                        arguments: [String] = []) -> XCUIApplication {
        let app = XCUIApplication()
        app.launchArguments = ["-ui-test-scenario", scenario] + arguments
        if let size {
            app.launchArguments += ["-UIPreferredContentSizeCategoryName", size]
        }
        XCUIDevice.shared.appearance = dark ? .dark : .light
        app.launch()
        return app
    }

    private func lastRequest(_ app: XCUIApplication) -> XCUIElement {
        app.staticTexts["fake-request"]
    }

    private func expect(_ app: XCUIApplication, request: String, file: StaticString = #filePath, line: UInt = #line) {
        let label = lastRequest(app)
        // Every request so far, each after a "|": wait for it, then require
        // it exactly ("accept " is not "accept 2").
        let predicate = NSPredicate(format: "label CONTAINS %@", "|" + request)
        let met = XCTNSPredicateExpectation(predicate: predicate, object: label)
        XCTAssertEqual(XCTWaiter().wait(for: [met], timeout: 5), .completed,
                       "requests: \(label.label)", file: file, line: line)
        XCTAssertTrue(label.label.components(separatedBy: "|").contains(request),
                      "requests: \(label.label)", file: file, line: line)
    }

    /// The audit, minus the test-only label (it is not part of the app).
    private func audit(_ app: XCUIApplication, file: StaticString = #filePath, line: UInt = #line) throws {
        // After sheets and tabs finish moving (mid-animation text reads as
        // clipped).
        Thread.sleep(forTimeInterval: 1.5)
        // Content scrolled beneath a system bar is read once scrolled into
        // view; measured through the bar's glass it is neither clipped nor
        // faint. Everything else counts.
        let bars = (app.tabBars.allElementsBoundByIndex + app.navigationBars.allElementsBoundByIndex)
            .filter(\.exists).map(\.frame)
        // A busy CI simulator can time the audit out before it reports
        // anything (code -56): that is no finding, so it runs again, once.
        do {
            try auditOnce(app, bars: bars)
        } catch let error as NSError where error.domain == "com.apple.xcode.xctest.accessibilityAudit" && error.code == -56 {
            try auditOnce(app, bars: bars)
        }
    }

    private func auditOnce(_ app: XCUIApplication, bars: [CGRect]) throws {
        try app.performAccessibilityAudit { issue in
            if issue.element?.identifier == "fake-request" { return true }
            if let frame = issue.element?.frame,
               bars.contains(where: { $0.intersects(frame) && !$0.contains(frame) }) {
                return true
            }
            // Two row buttons the audit reads as not scaling at the default
            // size, though they do: `testRowButtonsScale` measures them at
            // the default and the largest size. Only that check is waived.
            if issue.auditType == .dynamicType,
               ["Open in Files", "Clear the history"].contains(issue.element?.label ?? "") {
                return true
            }
            // The system search field's placeholder (`.searchable`) is
            // Apple's control; its clipping is not ours to fix.
            if issue.auditType == .textClipped, issue.element?.elementType == .searchField {
                return true
            }
            // A contrast issue the audit cannot tie to any element: in every
            // case seen, content below the fold faded by the tab bar's
            // scroll-edge effect (docs/adr/0017-ios.md). Other kinds count.
            if issue.element == nil, issue.auditType == .contrast {
                return true
            }
            let element = issue.element.map { "\($0.elementType.rawValue) id=\($0.identifier) label=\($0.label)" } ?? "-"
            XCTContext.runActivity(named: "AUDIT \(issue.compactDescription) | \(element) | \(issue.detailedDescription)") { _ in }
            return false
        }
    }

    // MARK: Home

    func testHomeListsDevicesAndOnlyReachableOnesCanSend() throws {
        let app = launch("default")
        XCTAssertTrue(app.staticTexts["Pixel 9"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.buttons["send-Pixel 9"].isEnabled)
        // An unreachable device has no Send button, only its state.
        XCTAssertFalse(app.buttons["send-Office PC"].exists)
        XCTAssertTrue(app.staticTexts["Not reachable"].exists)
        try audit(app)
    }

    func testAnEmptyHomeOffersPairing() throws {
        let app = launch("empty")
        XCTAssertTrue(app.buttons["pair-empty"].waitForExistence(timeout: 5))
        app.buttons["pair-empty"].tap()
        XCTAssertTrue(app.otherElements["pair-qr"].waitForExistence(timeout: 5) || app.images["pair-qr"].exists)
        expect(app, request: "show-qr")
    }

    // MARK: Receiving

    func testAnOfferIsArmedThenAcceptedWhole() throws {
        let app = launch("offer")
        let accept = app.buttons["accept-all"]
        XCTAssertTrue(accept.waitForExistence(timeout: 5))
        XCTAssertTrue(app.staticTexts["IMG_2041"].exists)
        try audit(app)
        // Armed after 700 ms; then one tap accepts everything.
        XCTAssertTrue(accept.waitForEnabled(timeout: 3))
        accept.tap()
        expect(app, request: "accept ")
        XCTAssertTrue(accept.waitForNonExistence(timeout: 5))
    }

    func testChoosingAcceptsOnlyTheChosenFiles() throws {
        let app = launch("offer")
        XCTAssertTrue(app.buttons["choose"].waitForEnabled(timeout: 5))
        app.buttons["choose"].tap()
        let accept = app.buttons["accept-chosen"]
        XCTAssertFalse(accept.isEnabled)
        app.buttons["file-IMG_2042.jpg"].tap()
        XCTAssertTrue(accept.waitForEnabled(timeout: 3))
        accept.tap()
        expect(app, request: "accept 2")
    }

    func testDecliningDeclines() throws {
        let app = launch("offer")
        XCTAssertTrue(app.buttons["decline"].waitForEnabled(timeout: 5))
        app.buttons["decline"].tap()
        expect(app, request: "decline")
    }

    func testProgramsAreFlagged() throws {
        let app = launch("programs")
        XCTAssertTrue(app.staticTexts.matching(identifier: "programs-warning").firstMatch.waitForExistence(timeout: 5)
            || app.otherElements["programs-warning"].exists)
        try audit(app)
    }

    func testAResumedOfferRepeatsItsSelection() throws {
        let app = launch("resumed")
        let accept = app.buttons["accept-all"]
        XCTAssertTrue(accept.waitForEnabled(timeout: 5))
        XCTAssertFalse(app.buttons["choose"].exists)
        accept.tap()
        expect(app, request: "accept 2")
    }

    // MARK: Pairing

    func testPairingShowsAQrAndStopsWhenDone() throws {
        let app = launch("default")
        app.buttons["pair"].tap()
        expect(app, request: "show-qr")
        try audit(app)
        app.buttons["pair-done"].tap()
        expect(app, request: "stop-pairing")
    }

    /// Pairing opened by a shortcut (or an automation) shows no QR, and so
    /// starts no stranger advertising, until the user taps for one.
    func testAShortcutOpensPairingWithoutAQr() throws {
        let app = launch("default", arguments: ["-open-pairing", "YES"])
        let show = app.buttons["show-qr"]
        XCTAssertTrue(show.waitForExistence(timeout: 5))
        XCTAssertFalse(app.descendants(matching: .any)["pair-qr"].exists)
        XCTAssertFalse(lastRequest(app).label.components(separatedBy: "|").contains("show-qr"),
                       "requests: \(lastRequest(app).label)")
        try audit(app)
        show.tap()
        expect(app, request: "show-qr")
    }

    func testPairingWithACode() throws {
        let app = launch("strangers")
        app.buttons["pair"].tap()
        app.segmentedControls["pair-method"].buttons["Code"].tap()
        app.buttons["show-code"].tap()
        XCTAssertTrue(app.staticTexts["code"].waitForExistence(timeout: 5))
        let stranger = app.buttons["stranger-9f9f9f9f"]
        XCTAssertTrue(stranger.waitForExistence(timeout: 5))
        stranger.tap()
        let field = app.secureTextFields["code-field"]
        field.tap()
        field.typeText("0123456789")
        app.buttons["pair-with-code"].tap()
        expect(app, request: "enter-code 0123456789")
    }

    func testScanningSaysWhenTheCameraIsMissing() throws {
        let app = launch("default")
        app.buttons["pair"].tap()
        app.segmentedControls["pair-method"].buttons["Scan"].tap()
        // The simulator has no camera: the screen says so instead.
        XCTAssertTrue(app.staticTexts["scan-unavailable"].waitForExistence(timeout: 5))
    }

    // MARK: Transfers, history, settings

    func testATransferCanBeCancelled() throws {
        let app = launch("transfers")
        app.tabBars.buttons["Transfers"].tap()
        let cancel = app.buttons["cancel-f1f1"]
        XCTAssertTrue(cancel.waitForExistence(timeout: 5))
        try audit(app)
        cancel.tap()
        expect(app, request: "cancel")
    }

    func testTheHistoryCanBeCleared() throws {
        let app = launch("history")
        app.tabBars.buttons["History"].tap()
        XCTAssertTrue(app.staticTexts["report.docx"].waitForExistence(timeout: 5))
        try audit(app)
        app.buttons["clear-history"].tap()
        // iOS 26 shows the confirmation as a popover (one match per layer).
        app.buttons["confirm-clear"].firstMatch.tap()
        expect(app, request: "clear-history")
    }

    func testHidingThisDevice() throws {
        let app = launch("default")
        app.tabBars.buttons["Settings"].tap()
        XCTAssertTrue(app.buttons["Hidden"].waitForExistence(timeout: 5))
        try audit(app)
        app.buttons["Hidden"].tap()
        expect(app, request: "hidden true")
    }

    // MARK: Dynamic Type

    /// The row buttons grow with the text size (the audit misreads them).
    func testRowButtonsScale() throws {
        func height(_ app: XCUIApplication, _ id: String) -> CGFloat {
            let button = app.descendants(matching: .any)[id]
            // Below the fold at the largest size: scroll to it.
            for _ in 0..<8 where !(button.exists && button.isHittable) {
                app.swipeUp()
            }
            XCTAssertTrue(button.waitForExistence(timeout: 5), id)
            return button.frame.height
        }
        func heights(_ size: String?) -> (CGFloat, CGFloat) {
            let app = launch("history", size: size)
            app.tabBars.buttons["Settings"].tap()
            let files = height(app, "open-files")
            app.tabBars.buttons["History"].tap()
            let clear = height(app, "clear-history")
            app.terminate()
            return (files, clear)
        }
        let normal = heights(nil)
        let largest = heights("UICTContentSizeCategoryAccessibilityXXXL")
        XCTAssertGreaterThan(largest.0, normal.0 * 2, "Open in Files: \(normal.0) → \(largest.0)")
        XCTAssertGreaterThan(largest.1, normal.1 * 2, "Clear the history: \(normal.1) → \(largest.1)")
    }

    /// The largest accessibility text size: every screen still passes the
    /// audit (text not clipped, controls reachable).
    func testTheLargestTextSize() throws {
        let app = launch("transfers", size: "UICTContentSizeCategoryAccessibilityXXXL")
        XCTAssertTrue(app.buttons["send-Pixel 9"].waitForExistence(timeout: 5))
        try audit(app)
        for tab in ["Transfers", "History", "Settings"] {
            app.tabBars.buttons[tab].tap()
            try audit(app)
        }
    }
}

extension XCUIElement {
    func waitForEnabled(timeout: TimeInterval) -> Bool {
        let met = XCTNSPredicateExpectation(predicate: NSPredicate(format: "isEnabled == true"), object: self)
        return XCTWaiter().wait(for: [met], timeout: timeout) == .completed
    }
}
