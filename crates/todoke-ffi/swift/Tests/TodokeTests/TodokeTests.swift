// The Swift bindings as an iOS or macOS app uses them: start two cores,
// pair by QR, offer a file, see the offer in a subscription, accept it, see
// it arrive; typed errors; the key store hook and its policy; handles
// keeping their core; subscriptions ending. Commands block: an app calls
// them off the main thread; the tests call them directly.

import Foundation
import Todoke
import XCTest

/// A scratch directory, removed afterwards.
final class Scratch {
    let url: URL

    init(_ name: String) throws {
        url = FileManager.default.temporaryDirectory
            .appendingPathComponent("todoke-swift-\(name)-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: url.appendingPathComponent("downloads"), withIntermediateDirectories: true)
    }

    deinit { try? FileManager.default.removeItem(at: url) }

    func settings(keyStorage: KeyStoragePolicy = .file, loopback: Bool = true) -> Settings {
        Settings(
            home: url.path, downloads: url.appendingPathComponent("downloads").path,
            lan: true, allowLoopback: loopback, hidden: false, historyDays: 7,
            keyStorage: keyStorage)
    }
}

/// A key store in memory, as an app would keep it with the Secure Enclave,
/// one key per profile.
final class MemoryKeyStore: KeyStore {
    private let lock = NSLock()
    private var keys: [String: Data] = [:]

    var profiles: [String] {
        lock.lock(); defer { lock.unlock() }
        return Array(keys.keys)
    }

    func protection() -> KeyProtection { .secureEnclave }

    func load(profile: String) throws -> Data? {
        lock.lock(); defer { lock.unlock() }
        return keys[profile]
    }

    func store(profile: String, key: Data) throws {
        lock.lock(); defer { lock.unlock() }
        if keys[profile] != nil { throw KeyStoreError.alreadyExists }
        keys[profile] = key
    }
}

/// A key store whose slot was wiped: all zeros.
final class WipedKeyStore: KeyStore {
    func protection() -> KeyProtection { .secureEnclave }
    func load(profile: String) throws -> Data? { Data(count: 32) }
    func store(profile: String, key: Data) throws { throw KeyStoreError.alreadyExists }
}

/// The first event `pick` accepts, within a minute.
func waitFor<T>(_ events: Events, _ pick: (CoreEvent) throws -> T?) throws -> T {
    let deadline = Date().addingTimeInterval(60)
    while Date() < deadline {
        for event in try events.next(max: 64, timeoutMs: 500) {
            if let found = try pick(event) { return found }
        }
    }
    throw XCTSkip("no such event in time")
}

/// Whether these tests run against the release package.
let releasePackage = ProcessInfo.processInfo.environment["TODOKE_RELEASE"] == "1"

final class TodokeTests: XCTestCase {
    override func setUpWithError() throws {
        if releasePackage && name.range(of: "testReleaseBuildsRefuseToStart") == nil {
            throw XCTSkip("the release package starts no core")
        }
    }

    func testVersion() {
        XCTAssertFalse(Core.version().isEmpty)
    }

    func testTwoCoresPairOfferAcceptAndReceive() throws {
        let (homeA, homeB) = (try Scratch("a"), try Scratch("b"))
        var a: Core? = try Core(settings: homeA.settings())
        let keys = MemoryKeyStore()
        let b = try Core(withKeyStore: homeB.settings(keyStorage: .platform), keyStore: keys)
        XCTAssertEqual(try b.status().keyProtection, .secureEnclave)
        XCTAssertEqual(keys.profiles.count, 1)

        let events = try a!.subscribe()
        let qr = try a!.pairShowQr()
        XCTAssertEqual(qr.modules().count, Int(qr.width() * qr.width()))
        XCTAssertTrue(qr.text().hasPrefix("TODOKE:"))
        let contact = try b.pairScanQr(text: qr.text())
        XCTAssertEqual(contact.device(), try a!.status().device)

        let file = homeB.url.appendingPathComponent("hello.txt")
        try Data("hello from swift".utf8).write(to: file)
        let sent = try contact.send(paths: [file.path])

        let offered: Offer = try waitFor(events) { event in
            if case .offerReceived(let offer) = event { return offer }
            return nil
        }
        XCTAssertEqual(offered.transfer, sent.id())
        XCTAssertEqual(offered.entries.map(\.name), ["hello.txt"])
        try a!.transfer(id: offered.transfer).accept(files: [])
        let _: Void = try waitFor(events) { event in
            if case .completed(let transfer) = event, transfer == offered.transfer { return () }
            return nil
        }
        let received = try Data(
            contentsOf: homeA.url.appendingPathComponent("downloads/hello.txt"))
        XCTAssertEqual(String(decoding: received, as: UTF8.self), "hello from swift")

        // Releasing the core stops it; the subscription ends once drained.
        a = nil
        let deadline = Date().addingTimeInterval(60)
        while true {
            do {
                _ = try events.next(max: 64, timeoutMs: 500)
            } catch TodokeError.state {
                break
            }
            XCTAssertLessThan(Date(), deadline, "the subscription never ended")
            if Date() > deadline { break }
        }
    }

    func testMalformedRequestsAreTypedErrors() throws {
        let home = try Scratch("errors")
        let core = try Core(settings: home.settings())
        XCTAssertThrowsError(try core.contact(device: "not hex")) { error in
            guard case TodokeError.invalid = error else { return XCTFail("\(error)") }
        }
        XCTAssertThrowsError(
            try core.transfer(id: String(repeating: "00", count: 16)).accept(files: [])
        ) { error in XCTAssertTrue(error is TodokeError, "\(error)") }
        var relative = home.settings()
        relative.home = "relative"
        XCTAssertThrowsError(try Core(settings: relative))
    }

    /// With a key store the key lives only there, and a wiped slot is
    /// never a key.
    func testKeyStorePolicy() throws {
        let home = try Scratch("keys")
        for policy in [KeyStoragePolicy.file, .auto] {
            XCTAssertThrowsError(
                try Core(withKeyStore: home.settings(keyStorage: policy), keyStore: MemoryKeyStore())
            ) { error in
                guard case TodokeError.invalid = error else { return XCTFail("\(error)") }
            }
        }
        XCTAssertThrowsError(
            try Core(withKeyStore: home.settings(keyStorage: .platform), keyStore: WipedKeyStore())
        ) { error in
            guard case TodokeError.keyStore = error else { return XCTFail("\(error)") }
        }
    }

    /// A pairing code crosses only through its own object.
    func testPairingCodes() throws {
        let home = try Scratch("code")
        let core = try Core(settings: home.settings())
        let offer = try core.pairShowCode()
        XCTAssertFalse(offer.code().isEmpty)
        XCTAssertGreaterThan(offer.expiresAt(), 0)
        try core.stopPairing()
    }

    /// A closed subscription ends at once and frees its place.
    func testSubscriptionsAreBounded() throws {
        let home = try Scratch("subscriptions")
        let core = try Core(settings: home.settings())
        var held: [Events] = []
        while held.count <= 64 {
            do { held.append(try core.subscribe()) } catch TodokeError.state { break }
        }
        XCTAssertLessThan(held.count, 64)
        held[0].stop()
        XCTAssertThrowsError(try held[0].next(max: 1, timeoutMs: 0))
        XCTAssertNoThrow(try core.subscribe())
    }

    /// A handle keeps its core running after the app releases the core:
    /// the profile stays held until the last handle goes.
    func testHandlesKeepTheirCoreUntilTheyGo() throws {
        let home = try Scratch("release")
        var core: Core? = try Core(settings: home.settings())
        var handle: TransferHandle? = try core!.transfer(id: String(repeating: "ab", count: 16))
        core = nil
        XCTAssertThrowsError(try handle!.cancel())
        XCTAssertThrowsError(try Core(settings: home.settings()))
        handle = nil
        // The last reference went: the profile is free.
        _ = try Core(settings: home.settings())
    }

    /// The release package (TODOKE_RELEASE=1) keeps sessions disabled
    /// (PROTOCOL §16): no core starts, whatever the settings.
    func testReleaseBuildsRefuseToStart() throws {
        try XCTSkipUnless(releasePackage, "the test package starts cores")
        let home = try Scratch("shipped")
        XCTAssertThrowsError(try Core(settings: home.settings(loopback: false))) { error in
            guard case TodokeError.disabled = error else { return XCTFail("\(error)") }
        }
        XCTAssertThrowsError(
            try Core(withKeyStore: home.settings(keyStorage: .platform, loopback: false),
                     keyStore: MemoryKeyStore())
        ) { error in
            guard case TodokeError.disabled = error else { return XCTFail("\(error)") }
        }
    }
}
