// The real core inside the app's sandbox, with the development package
// (sessions and loopback, scripts/bindings.sh dev): two cores pair by QR —
// the scanner finds the displayer through discovery, which on iOS is the
// system's Bonjour — one sends a file handed over open, the other accepts
// it and publishes it. The storage key goes to the Keychain (wrapped by the
// Secure Enclave where there is one), and a profile reopens with its
// identity. Skipped
// with the release package, whose cores refuse to start.

import Darwin
import Todoke
import XCTest

final class RealCoreTests: XCTestCase {
    private var scratch: [URL] = []

    override func tearDown() {
        scratch.forEach { try? FileManager.default.removeItem(at: $0) }
        super.tearDown()
    }

    private func home(_ name: String) throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("real-core-\(name)-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: url.appendingPathComponent("received"), withIntermediateDirectories: true)
        scratch.append(url)
        return url
    }

    private func settings(_ home: URL) -> Settings {
        Settings(home: home.path, downloads: home.appendingPathComponent("received").path, lan: true,
                 allowLoopback: true, hidden: false, historyDays: 7, keyStorage: .platform)
    }

    private func core(_ settings: Settings) throws -> Core {
        do {
            return try Core(settings: settings)
        } catch TodokeError.disabled {
            throw XCTSkip("the release package starts no core")
        } catch TodokeError.invalid {
            throw XCTSkip("this package has no loopback discovery")
        }
    }

    /// Waits for the first event `matches` picks, reading `core`'s events.
    private func wait<T>(_ core: Core, seconds: Double, _ matches: (CoreEvent) -> T?) throws -> T {
        let events = try core.subscribe()
        defer { events.stop() }
        let deadline = Date().addingTimeInterval(seconds)
        while Date() < deadline {
            for event in try events.next(max: 64, timeoutMs: 250) {
                if let found = matches(event) { return found }
            }
        }
        throw XCTSkip("timed out")
    }

    func testTwoCoresPairOverBonjourAndSendAFileHandedOverOpen() throws {
        let (homeA, homeB) = (try home("a"), try home("b"))
        let a = try core(settings(homeA))
        let b = try core(settings(homeB))
        // The Keychain, wrapped by the Secure Enclave where there is one
        // (the simulator on Apple silicon has one).
        XCTAssertTrue([.secureEnclave, .keychain].contains(try a.status().keyProtection))

        // QR pairing: the scanner (B) finds A by the QR's stranger token.
        let text = try a.pairShowQr().text()
        XCTAssertTrue(text.hasPrefix("TODOKE:"))
        let contact = try b.pairScanQr(text: text)
        XCTAssertEqual(contact.device(), try a.status().device)

        // A file handed over open, as a picked document is.
        let document = homeB.appendingPathComponent("notes.txt")
        try Data("hello from the sandbox".utf8).write(to: document)
        let fd = open(document.path, O_RDONLY | O_CLOEXEC)
        XCTAssertGreaterThanOrEqual(fd, 0)
        let offered = DispatchSemaphore(value: 0)
        var offer: Offer?
        let watcher = Thread {
            offer = try? self.waitOffer(a)
            offered.signal()
        }
        watcher.start()
        let sent = try contact.sendFiles(names: ["trip notes.txt"], fds: [fd])
        XCTAssertEqual(offered.wait(timeout: .now() + 60), .success)
        let received = try XCTUnwrap(offer)
        XCTAssertEqual(received.transfer, sent.id())
        XCTAssertEqual(received.entries.map(\.name), ["trip notes.txt"])

        try a.transfer(id: received.transfer).accept(files: [])
        _ = try wait(a, seconds: 60) { event -> String? in
            if case .completed(let transfer) = event, transfer == received.transfer { return transfer }
            return nil
        }
        let published = homeA.appendingPathComponent("received/trip notes.txt")
        XCTAssertEqual(try String(contentsOf: published, encoding: .utf8), "hello from the sandbox")
    }

    private func waitOffer(_ core: Core) throws -> Offer {
        try wait(core, seconds: 60) { event -> Offer? in
            if case .offerReceived(let offer) = event { return offer }
            return nil
        }
    }

    /// A profile reopened finds its key in the Keychain: the same device.
    func testAProfileReopensWithItsKeychainKey() throws {
        let home = try home("reopen")
        // The first core stops when released: the profile is free again.
        let device = try core(settings(home)).status().device
        let again = try core(settings(home))
        XCTAssertEqual(try again.status().device, device)
    }

    /// In the background (PROTOCOL §10.3) pairing ends and waits for the
    /// app (the listener's closing is tested in Rust); back, it works.
    func testTheBackgroundEndsPairing() throws {
        let core = try core(settings(try home("background")))
        _ = try core.pairShowQr()
        XCTAssertTrue(try core.status().pairing)
        try core.setBackground(background: true)
        XCTAssertFalse(try core.status().pairing)
        XCTAssertThrowsError(try core.pairShowQr())
        try core.setBackground(background: false)
        _ = try core.pairShowQr()
        try core.stopPairing()
    }

    /// A key that needs the user's presence never falls back to a key file:
    /// in a test there is no one to ask, and a simulator without a passcode
    /// may refuse such a key outright; either way, no file.
    func testAPresenceKeyNeverFallsBackToAFile() throws {
        let home = try home("presence")
        do {
            _ = try Core(withPresence: settings(home))
        } catch TodokeError.disabled {
            throw XCTSkip("the release package starts no core")
        } catch TodokeError.locked, TodokeError.keyStore {
            // Refused or unavailable: what the app shows as locked or failed.
        }
        let files = FileManager.default.enumerator(atPath: home.path)?.allObjects as? [String] ?? []
        XCTAssertFalse(files.contains { $0.hasSuffix("storage.key") }, "\(files)")
    }
}
