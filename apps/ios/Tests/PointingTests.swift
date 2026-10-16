// Pointing against the scripted core. An iPhone that measures no precise
// distance is never pointable, points at nothing, and answers nothing; one
// that does prepares a session per target and answers a contact with a
// fresh one, once per ranging. Ranging itself needs two iPhones
// (docs/qa/radios.md).

import Todoke
@testable import TodokeApp
import XCTest

@MainActor
final class PointingTests: XCTestCase {
    private func waitFor(_ request: String, in fake: FakeBackend) async throws {
        let deadline = Date().addingTimeInterval(5)
        while !fake.requests.contains(request) {
            guard Date() < deadline else {
                XCTFail("no \(request) in \(fake.requests)")
                return
            }
            try await Task.sleep(for: .milliseconds(20))
        }
    }

    private func request(_ sessionId: UInt32) -> CoreEvent {
        .peerRangingRequested(ranging: PeerRangingInfo(
            contact: "a1", sessionId: sessionId, peerToken: Data([1, 2, 3]), localToken: nil))
    }

    func testWithoutPreciseDistanceNothingPoints() async throws {
        let fake = FakeBackend()
        let pointing = Pointing(backend: fake, capable: false)
        await pointing.setForeground(true)
        XCTAssertFalse(pointing.ready)
        XCTAssertEqual(fake.requests.last, "ranging-ready none")
        await pointing.start(nearby: 3)
        XCTAssertFalse(pointing.active)
        XCTAssertFalse(fake.requests.contains { $0.hasPrefix("point-start") })
        await pointing.setForeground(false)
    }

    func testANotReadyIPhoneAnswersNothing() async throws {
        let fake = FakeBackend()
        let pointing = Pointing(backend: fake, capable: false)
        await pointing.setForeground(true)
        // It announced nothing, so the core asks nothing; if asked anyway,
        // it neither accepts nor ranges.
        fake.emit(request(7))
        fake.emit(.peerPointTarget(ranging: PeerRangingInfo(
            contact: "a1", sessionId: 8, peerToken: Data([1]), localToken: Data([9]))))
        fake.emit(.rangingStopped(contact: "a1", sessionId: 7))
        try await Task.sleep(for: .milliseconds(300))
        XCTAssertFalse(fake.requests.contains { $0.hasPrefix("accept-ranging") })
        XCTAssertTrue(pointing.bearings.isEmpty)
        await pointing.setForeground(false)
    }

    func testPointingAndAnsweringWhenReady() async throws {
        try XCTSkipIf(
            Ranger(update: { _, _ in }, ended: { _ in }).token == nil,
            "Nearby Interaction gives no discovery token here")
        let fake = FakeBackend()
        let pointing = Pointing(backend: fake, capable: true)
        await pointing.setForeground(true)
        XCTAssertTrue(pointing.ready)
        XCTAssertEqual(fake.requests.last, "ranging-ready 2")
        // One session per target, at most four.
        await pointing.start(nearby: 9)
        XCTAssertTrue(pointing.active)
        XCTAssertTrue(fake.requests.contains("point-start 4"))
        // A contact points here: answered with a fresh session's token;
        // a second request for the same ranging is refused.
        fake.emit(request(7))
        try await waitFor("accept-ranging 7", in: fake)
        fake.emit(request(7))
        try await waitFor("refuse-ranging 7", in: fake)
        fake.emit(.rangingStopped(contact: "a1", sessionId: 7))
        // Leaving the screen ends readiness and pointing.
        await pointing.setForeground(false)
        XCTAssertFalse(pointing.ready)
        XCTAssertFalse(pointing.active)
        XCTAssertEqual(Array(fake.requests.suffix(2)), ["ranging-ready none", "point-stop"])
    }
}
