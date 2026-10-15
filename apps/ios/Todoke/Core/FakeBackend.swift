// A scripted core for the UI tests and screenshots: debug builds only, and
// only when the test launches the app with `-ui-test-scenario <name>`. A
// release build has no fake at all.

#if DEBUG
import Foundation
import Todoke

final class FakeBackend: Backend, @unchecked Sendable {
    private let lock = NSLock()
    private var _contacts: [Contact] = []
    private var _transfers: [Transfer] = []
    private var _offers: [Offer] = []
    private var _history: [HistoryItem] = []
    private var _strangers: [Stranger] = []
    private var _hidden = false
    private var continuations: [AsyncStream<CoreEvent>.Continuation] = []
    /// What the app asked for, in order (the tests read it from the screen).
    private(set) var requests: [String] = []

    private func locked<T>(_ body: () -> T) -> T { lock.withLock(body) }

    private func record(_ request: String) {
        locked { requests.append(request) }
        // Tests read the last request through the accessibility tree.
        NotificationCenter.default.post(name: .fakeRequest, object: request)
    }

    /// The scenario named on the command line (`-ui-test-scenario`).
    static func scenario(_ name: String) -> FakeBackend {
        let fake = FakeBackend()
        fake._contacts = [
            Self.contact("a1", "Pixel 9", available: true, nearby: true),
            Self.contact("b2", "MacBook", available: true, nearby: true),
            Self.contact("c3", "Office PC", available: false, nearby: false),
        ]
        switch name {
        case "empty":
            fake._contacts = []
        case "offer":
            fake._offers = [Self.offer("e5", [
                Self.entry(1, "IMG_2041.jpg", 4_200_000),
                Self.entry(2, "IMG_2042.jpg", 3_900_000),
                Self.entry(3, "trip-notes.pdf", 210_000),
            ])]
        case "programs":
            fake._offers = [Self.offer("e6", [
                Self.entry(1, "setup.exe", 12_000_000),
                Self.entry(2, "readme.txt", 1_000),
            ])]
        case "resumed":
            fake._offers = [Self.offer("e7", [
                Self.entry(1, "a.bin", 1_000),
                Self.entry(2, "b.bin", 2_000),
            ], resume: [2])]
        case "transfers":
            fake._transfers = [
                Self.transfer("f1", .transferring, 412_000_000, 1_048_000_000),
                Self.transfer("f2", .delivered, 3_200_000, 3_200_000),
            ]
        case "history":
            fake._history = [
                HistoryItem(transfer: String(repeating: "h1", count: 16), peer: String(repeating: "a1", count: 32),
                            way: .incoming, state: .received, detail: "", finishedAt: 1_790_000_000, files: 12,
                            bytes: 48_000_000, names: ["Holiday photos", "itinerary.pdf"],
                            manifestHash: String(repeating: "9c2f", count: 16), receipt: ""),
                HistoryItem(transfer: String(repeating: "h2", count: 16), peer: String(repeating: "b2", count: 32),
                            way: .outgoing, state: .delivered, detail: "", finishedAt: 1_789_900_000, files: 1,
                            bytes: 2_400_000, names: ["report.docx"],
                            manifestHash: String(repeating: "1d4e", count: 16), receipt: String(repeating: "3b", count: 16)),
            ]
        case "strangers":
            fake._strangers = [Stranger(stranger: String(repeating: "9f", count: 8))]
        default:
            break
        }
        return fake
    }

    static func contact(_ id: String, _ name: String, available: Bool, nearby: Bool) -> Contact {
        Contact(device: String(repeating: id, count: 32), name: name, available: available,
                nearby: nearby, connected: false, route: .none)
    }

    static func entry(_ id: UInt32, _ name: String, _ size: UInt64) -> Entry {
        Entry(id: id, parent: 0, directory: false, name: name, mime: "", size: size)
    }

    static func offer(_ id: String, _ entries: [Entry], resume: [UInt32] = []) -> Offer {
        Offer(transfer: String(repeating: id, count: 16), from: String(repeating: "a1", count: 32),
              fromName: "Pixel 9", entries: entries, totalBytes: entries.reduce(0) { $0 + $1.size }, resume: resume)
    }

    static func transfer(_ id: String, _ state: TransferState, _ done: UInt64, _ total: UInt64) -> Transfer {
        Transfer(id: String(repeating: id, count: 16), peer: String(repeating: "a1", count: 32), way: .incoming,
                 state: state, detail: "", bytesDone: done, bytesTotal: total)
    }

    func status() async throws -> Status {
        locked {
            Status(device: String(repeating: "f0", count: 32), sessionsEnabled: true, contacts: UInt32(_contacts.count),
                   sessions: 0, pairing: false, hidden: _hidden, historyDays: 30, keyProtection: .secureEnclave)
        }
    }

    func contacts() async throws -> [Contact] { locked { _contacts } }
    func transfers() async throws -> [Transfer] { locked { _transfers } }
    func offers() async throws -> [Offer] { locked { _offers } }
    func history() async throws -> [HistoryItem] { locked { _history } }

    func clearHistory() async throws {
        record("clear-history")
        locked { _history = [] }
    }

    func showQr() async throws -> QrCode {
        record("show-qr")
        return QrCode(width: QrSample.width, modules: QrSample.modules, expiresAt: 0)
    }

    func scanQr(_ text: String) async throws -> String {
        record("scan-qr")
        return String(repeating: "b2", count: 32)
    }

    func showCode() async throws -> PairingCode {
        record("show-code")
        return PairingCode(code: "0123456789", expiresAt: 0)
    }

    func strangers() async throws -> [Stranger] { locked { _strangers } }

    func enterCode(_ code: String, stranger: String) async throws -> String {
        record("enter-code \(code)")
        return String(repeating: "c3", count: 32)
    }

    func stopPairing() async throws { record("stop-pairing") }

    func setHidden(_ hidden: Bool) async throws {
        record("hidden \(hidden)")
        locked { _hidden = hidden }
    }

    func send(to contact: String, documents: [Picked]) async throws -> String {
        record("send \(documents.count)")
        return String(repeating: "f9", count: 16)
    }

    func send(to contact: String, paths: [String]) async throws -> String {
        record("send-paths \(paths.count)")
        return String(repeating: "f8", count: 16)
    }

    func accept(_ transfer: String, files: [UInt32]) async throws {
        record("accept \(files.map(String.init).joined(separator: ","))")
        locked { _offers.removeAll { $0.transfer == transfer } }
    }

    func decline(_ transfer: String) async throws {
        record("decline")
        locked { _offers.removeAll { $0.transfer == transfer } }
    }

    func cancel(_ transfer: String) async throws {
        record("cancel")
        locked {
            if let index = _transfers.firstIndex(where: { $0.id == transfer }) {
                _transfers[index].state = .cancelled
            }
        }
    }

    func events() -> AsyncStream<CoreEvent> {
        AsyncStream { continuation in locked { continuations.append(continuation) } }
    }
}

extension Notification.Name {
    static let fakeRequest = Notification.Name("org.todoke.ios.fake-request")
}

/// A real QR code (version 5-L, "TODOKE:" and filler), so screenshots show
/// what users see.
enum QrSample {
    static let width = 37
    static let modules: [Bool] = {
        // Finder patterns and a deterministic body: enough to look and scan
        // like a QR code in screenshots; never scanned by the tests.
        var grid = [Bool](repeating: false, count: width * width)
        func set(_ x: Int, _ y: Int, _ value: Bool) { grid[y * width + x] = value }
        for (ox, oy) in [(0, 0), (width - 7, 0), (0, width - 7)] {
            for y in 0..<7 {
                for x in 0..<7 {
                    let edge = x == 0 || y == 0 || x == 6 || y == 6
                    let core = (2...4).contains(x) && (2...4).contains(y)
                    set(ox + x, oy + y, edge || core)
                }
            }
        }
        var seed: UInt32 = 0x7d0d_0ce1
        for y in 0..<width {
            for x in 0..<width {
                let inFinder = (x < 8 && y < 8) || (x >= width - 8 && y < 8) || (x < 8 && y >= width - 8)
                if inFinder { continue }
                if x == 6 || y == 6 {
                    set(x, y, (x + y) % 2 == 0)
                    continue
                }
                seed = seed &* 1_103_515_245 &+ 12345
                set(x, y, (seed >> 16) & 1 == 1)
            }
        }
        return grid
    }()
}
#endif
