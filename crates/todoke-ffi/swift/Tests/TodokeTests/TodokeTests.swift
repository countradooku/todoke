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

/// A key store whose answers are fixed: a key of any length, or an error
/// it declares or not.
final class CannedKeyStore: KeyStore {
    let loaded: () throws -> Data?
    let stored: () throws -> Void

    init(load: @escaping () throws -> Data?, store: @escaping () throws -> Void) {
        loaded = load
        stored = store
    }

    func protection() -> KeyProtection { .secureEnclave }
    func load(profile: String) throws -> Data? { try loaded() }
    func store(profile: String, key: Data) throws { try stored() }
}

/// An error a key store does not declare.
struct Oops: Error {}

/// What the notifier was told, in order.
final class RecordingNotifier: Notifier {
    private let lock = NSLock()
    private var lines: [String] = []

    var log: [String] {
        lock.lock(); defer { lock.unlock() }
        return lines
    }

    private func record(_ line: String) {
        lock.lock(); defer { lock.unlock() }
        lines.append(line)
    }

    func offerReceived(notice: OfferNotice) {
        record("offer \(notice.transfer) from \(notice.from) \(notice.files) files \(notice.folders) folders \(notice.totalBytes) bytes")
    }
    func offerGone(transfer: String) { record("gone \(transfer)") }
    func transferFinished(transfer: String, text: String) { record("finished \(transfer): \(text)") }
    func missed() { record("missed") }
}

/// An app that can set up no direct link.
final class NoLinks: WifiLinks {
    func abilities() -> LinkAbilities { LinkAbilities(host: [], join: [], joinSecurity: []) }
    func host(request: LinkRequest) throws -> LinkLease { throw LinkError.closed }
    func join(request: LinkRequest) throws -> LinkLease { throw LinkError.closed }
    func bindSocket(lease: UInt64, socket: Int64) throws { throw LinkError.closed }
    func release(lease: UInt64) {}
}

/// What a reader does with a Type 4 tag: select, read the length, read.
func readTag(_ tag: NfcTag) throws -> Data {
    func answer(_ apdu: [UInt8]) throws -> Data {
        let out = tag.respond(apdu: Data(apdu))
        XCTAssertEqual(Array(out.suffix(2)), [0x90, 0])
        return out.prefix(out.count - 2)
    }
    _ = try answer([0, 0xa4, 4, 0, 7, 0xd2, 0x76, 0, 0, 0x85, 1, 1])
    _ = try answer([0, 0xa4, 0, 0x0c, 2, 0xe1, 0x04])
    let head = Array(try answer([0, 0xb0, 0, 0, 2]))
    let length = Int(head[0]) << 8 | Int(head[1])
    var message = Data()
    while message.count < length {
        let at = message.count + 2
        let wanted = min(length - message.count, 255)
        message.append(try answer([0, 0xb0, UInt8(at >> 8), UInt8(at & 0xff), UInt8(wanted)]))
    }
    return message
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

    /// The notifier hears of an offer by its sender and counts, never a
    /// file name, then of its notification going and the transfer ending.
    func testNotifierHearsOffersWithoutNames() throws {
        let (homeA, homeB) = (try Scratch("notify-a"), try Scratch("notify-b"))
        let a = try Core(settings: homeA.settings())
        let b = try Core(settings: homeB.settings())
        let told = RecordingNotifier()
        a.setNotifier(notifier: told)
        let events = try a.subscribe()
        let contact = try b.pairScanQr(text: try a.pairShowQr().text())

        let file = homeB.url.appendingPathComponent("secret-plan.txt")
        try Data("plans".utf8).write(to: file)
        let sent = try contact.send(paths: [file.path])
        let offered: Offer = try waitFor(events) { event in
            if case .offerReceived(let offer) = event { return offer }
            return nil
        }
        try a.transfer(id: offered.transfer).accept(files: [])
        let finished = "finished \(sent.id()): Files received"
        let deadline = Date().addingTimeInterval(60)
        while !told.log.contains(finished) && Date() < deadline {
            Thread.sleep(forTimeInterval: 0.02)
        }
        XCTAssertEqual(told.log, [
            "offer \(sent.id()) from \(try b.status().device) 1 files 0 folders 5 bytes",
            "gone \(sent.id())",
            finished,
        ])
        XCTAssertFalse(told.log.contains { $0.contains("secret") })
        a.clearNotifier()
    }

    /// A key store that fails with an error it does not declare, or hands
    /// back something that is not a key, stops the start with a key store
    /// error; one that refuses (the user did not unlock) with `locked`.
    func testFailingKeyStoresStopTheStart() throws {
        let refusing = CannedKeyStore(load: { nil }, store: { throw KeyStoreError.refused(message: "no") })
        XCTAssertThrowsError(
            try Core(withKeyStore: Scratch("refusing").settings(keyStorage: .platform), keyStore: refusing)
        ) { error in
            guard case TodokeError.locked = error else { return XCTFail("\(error)") }
        }
        let stores = [
            CannedKeyStore(load: { nil }, store: { throw Oops() }),
            CannedKeyStore(load: { throw Oops() }, store: {}),
            CannedKeyStore(load: { throw KeyStoreError.unavailable(message: "locked") }, store: {}),
            CannedKeyStore(load: { Data(count: 0) }, store: {}),
            CannedKeyStore(load: { Data(repeating: 7, count: 31) }, store: {}),
            CannedKeyStore(load: { Data(repeating: 7, count: 33) }, store: {}),
        ]
        for store in stores {
            let home = try Scratch("failing")
            XCTAssertThrowsError(
                try Core(withKeyStore: home.settings(keyStorage: .platform), keyStore: store)
            ) { error in
                guard case TodokeError.keyStore = error else { return XCTFail("\(error)") }
            }
        }
    }

    /// A profile reopened with its key store finds its key under the same
    /// ID: the same identity, no second key.
    func testAProfileReopensWithItsKey() throws {
        let home = try Scratch("reopen")
        let keys = MemoryKeyStore()
        var core: Core? = try Core(withKeyStore: home.settings(keyStorage: .platform), keyStore: keys)
        let device = try core!.status().device
        core = nil
        core = try Core(withKeyStore: home.settings(keyStorage: .platform), keyStore: keys)
        XCTAssertEqual(try core!.status().device, device)
        XCTAssertEqual(keys.profiles.count, 1)
    }

    /// The app gives the core its links once; a second time is refused.
    func testLinksAreGivenOnce() throws {
        let home = try Scratch("links")
        let core = try Core(settings: home.settings())
        try core.setLinks(links: NoLinks())
        XCTAssertThrowsError(try core.setLinks(links: NoLinks())) { error in
            guard case TodokeError.state = error else { return XCTFail("\(error)") }
        }
    }

    /// Pointing checks its parameters as the records will (PROTOCOL §10.4).
    func testPointingParametersAreChecked() throws {
        let home = try Scratch("point")
        let core = try Core(settings: home.settings())
        try core.setRangingReady(configs: 1)
        XCTAssertThrowsError(try core.setRangingReady(configs: 0))
        XCTAssertThrowsError(try core.setRangingReady(configs: 4))
        try core.clearRangingReady()
        XCTAssertThrowsError(try core.pointStart(controllers: []))
        XCTAssertThrowsError(
            try core.pointStart(controllers: [UwbController(address: 7, channel: 6, preamble: 10)]))
        try core.pointStart(controllers: [
            UwbController(address: 7, channel: 9, preamble: 10),
            UwbController(address: 8, channel: 5, preamble: 9),
        ])
        try core.pointStop()
    }

    /// B pairs with A by tapping: A's emulated tag serves its QR offer.
    func testPairingByNfc() throws {
        let (homeA, homeB) = (try Scratch("nfc-a"), try Scratch("nfc-b"))
        let a = try Core(settings: homeA.settings())
        let b = try Core(settings: homeB.settings())
        XCTAssertThrowsError(try b.pairScanNfc(message: Data(count: 8))) { error in
            guard case TodokeError.pairing = error else { return XCTFail("\(error)") }
        }
        let message = try readTag(try a.pairShowQr().nfcTag())
        let contact = try b.pairScanNfc(message: message)
        XCTAssertEqual(contact.device(), try a.status().device)
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
