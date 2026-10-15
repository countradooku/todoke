// The Swift bindings as an iOS or macOS app uses them: start two cores,
// pair by QR, offer a file, see the offer on the event stream, accept it,
// see it arrive; typed errors; the key store hook; releasing a core.

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

    func settings(keyStorage: KeyStoragePolicy = .file) -> Settings {
        Settings(
            home: url.path, downloads: url.appendingPathComponent("downloads").path,
            lan: true, allowLoopback: true, hidden: false, historyDays: 7,
            keyStorage: keyStorage)
    }
}

/// A key store in memory, as an app would keep it with the Secure Enclave.
final class MemoryKeyStore: KeyStore {
    private let lock = NSLock()
    private var key: Data?
    private(set) var stores = 0

    func protection() -> KeyProtection { .secureEnclave }

    func load() throws -> Data? {
        lock.lock(); defer { lock.unlock() }
        return key
    }

    func store(key: Data) throws {
        lock.lock(); defer { lock.unlock() }
        if self.key != nil { throw KeyStoreError.alreadyExists }
        self.key = key
        stores += 1
    }
}

final class TodokeTests: XCTestCase {
    func testVersion() {
        XCTAssertFalse(Core.version().isEmpty)
    }

    func testTwoCoresPairOfferAcceptAndReceive() async throws {
        let (homeA, homeB) = (try Scratch("a"), try Scratch("b"))
        let a = try Core(settings: homeA.settings())
        let keys = MemoryKeyStore()
        let b = try Core(withKeyStore: homeB.settings(keyStorage: .platform), keyStore: keys)
        let status = try await b.status()
        XCTAssertEqual(status.keyProtection, .secureEnclave)
        XCTAssertEqual(keys.stores, 1)

        let events = a.events()
        let qr = try await a.pairShowQr()
        XCTAssertEqual(qr.modules().count, Int(qr.width() * qr.width()))
        XCTAssertTrue(qr.text().hasPrefix("TODOKE:"))
        let contact = try await b.pairScanQr(text: qr.text())
        let device = try await a.status().device
        XCTAssertEqual(contact.device(), device)

        let file = homeB.url.appendingPathComponent("hello.txt")
        try Data("hello from swift".utf8).write(to: file)
        let sent = try await contact.send(paths: [file.path])

        var offered: Offer?
        var completed = false
        for await event in events {
            switch event {
            case .offerReceived(let offer) where offered == nil:
                XCTAssertEqual(offer.transfer, sent.id())
                XCTAssertEqual(offer.entries.map(\.name), ["hello.txt"])
                offered = offer
                try await a.transfer(id: offer.transfer).accept(files: [])
            case .completed(let transfer) where transfer == offered?.transfer:
                completed = true
            default:
                break
            }
            if completed { break }
        }
        XCTAssertTrue(completed)
        let received = try Data(
            contentsOf: homeA.url.appendingPathComponent("downloads/hello.txt"))
        XCTAssertEqual(String(decoding: received, as: UTF8.self), "hello from swift")
    }

    func testMalformedRequestsAreTypedErrors() async throws {
        let home = try Scratch("errors")
        let core = try Core(settings: home.settings())
        XCTAssertThrowsError(try core.contact(device: "not hex")) { error in
            guard case TodokeError.invalid = error else {
                return XCTFail("\(error)")
            }
        }
        do {
            try await core.transfer(id: String(repeating: "00", count: 16)).accept(files: [])
            XCTFail("an unknown transfer was accepted")
        } catch is TodokeError {}
        var relative = home.settings()
        relative.home = "relative"
        XCTAssertThrowsError(try Core(settings: relative))
    }

    /// A handle keeps its core running after the app releases the core:
    /// the profile stays held until the last handle goes.
    func testHandlesKeepTheirCoreUntilTheyGo() async throws {
        let home = try Scratch("release")
        var core: Core? = try Core(settings: home.settings())
        var handle: TransferHandle? = try core!.transfer(id: String(repeating: "ab", count: 16))
        core = nil
        do {
            try await handle!.cancel()
        } catch is TodokeError {}
        XCTAssertThrowsError(try Core(settings: home.settings()))
        handle = nil
        // The last reference went: the profile is free.
        _ = try Core(settings: home.settings())
    }
}
