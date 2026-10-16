// The Backend on the real core (the BoltFFI Swift package). Calls block in
// the core, so they run off the main actor, one at a time on a serial
// queue of their own. Picked documents are handed to the core open: the
// app opens each (inside its security scope) and the core adopts the
// descriptor, never seeing a path or a copy.

import Darwin
import Foundation
import Todoke

final class CoreBackend: Backend, @unchecked Sendable {
    private let core: Core
    private let queue = DispatchQueue(label: "org.todoke.ios.core")

    init(core: Core) {
        self.core = core
    }

    private func call<T>(_ body: @escaping (Core) throws -> T) async throws -> T {
        try await withCheckedThrowingContinuation { continuation in
            queue.async { [core] in
                continuation.resume(with: Result { try body(core) })
            }
        }
    }

    func status() async throws -> Status { try await call { try $0.status() } }
    func contacts() async throws -> [Contact] { try await call { try $0.contacts() } }
    func transfers() async throws -> [Transfer] { try await call { try $0.transfers() } }
    func offers() async throws -> [Offer] { try await call { try $0.offers() } }
    func history() async throws -> [HistoryItem] { try await call { try $0.history() } }
    func clearHistory() async throws { try await call { try $0.clearHistory() } }

    func showQr() async throws -> QrCode {
        try await call { core in
            let offer = try core.pairShowQr()
            let width = Int(offer.width())
            return QrCode(width: width, modules: offer.modules().map { $0 != 0 }, expiresAt: offer.expiresAt())
        }
    }

    func scanQr(_ text: String) async throws -> String {
        try await call { try $0.pairScanQr(text: text).device() }
    }

    func showCode() async throws -> PairingCode {
        try await call { core in
            let offer = try core.pairShowCode()
            return PairingCode(code: offer.code(), expiresAt: offer.expiresAt())
        }
    }

    func strangers() async throws -> [Stranger] { try await call { try $0.strangers() } }

    func enterCode(_ code: String, stranger: String) async throws -> String {
        try await call { try $0.pairEnterCode(code: code, stranger: stranger).device() }
    }

    func stopPairing() async throws { try await call { try $0.stopPairing() } }
    func setHidden(_ hidden: Bool) async throws { try await call { try $0.setHidden(hidden: hidden) } }

    func setBackground(_ background: Bool) async throws {
        try await call { try $0.setBackground(background: background) }
    }

    func send(to contact: String, documents: [Picked]) async throws -> String {
        var fds: [Int32] = []
        // Whatever was opened and not yet handed over is closed again.
        defer { fds.forEach { Darwin.close($0) } }
        for document in documents {
            let scoped = document.url.startAccessingSecurityScopedResource()
            defer { if scoped { document.url.stopAccessingSecurityScopedResource() } }
            let fd = Darwin.open(document.url.path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
            guard fd >= 0 else { throw CocoaError(.fileReadNoPermission) }
            fds.append(fd)
        }
        let names = documents.map(\.name)
        let handed = fds
        // Handed over now: the core owns and closes them, whatever happens.
        fds = []
        return try await call { core in
            try core.contact(device: contact).sendFiles(names: names, fds: handed).id()
        }
    }

    func send(to contact: String, paths: [String]) async throws -> String {
        try await call { try $0.contact(device: contact).send(paths: paths).id() }
    }

    func accept(_ transfer: String, files: [UInt32]) async throws {
        try await call { try $0.transfer(id: transfer).accept(files: files) }
    }

    func decline(_ transfer: String) async throws { try await call { try $0.transfer(id: transfer).decline() } }
    func cancel(_ transfer: String) async throws { try await call { try $0.transfer(id: transfer).cancel() } }

    func events() -> AsyncStream<CoreEvent> {
        let core = core
        return AsyncStream { continuation in
            // A subscription read on a thread of its own: each read blocks
            // up to 250 ms, then checks whether reading is still wanted.
            let stop = Stopper()
            let thread = Thread {
                guard let events = try? core.subscribe() else {
                    continuation.finish()
                    return
                }
                defer { events.stop() }
                while !stop.stopped {
                    guard let batch = try? events.next(max: 64, timeoutMs: 250) else { break }
                    batch.forEach { continuation.yield($0) }
                }
                continuation.finish()
            }
            thread.name = "todoke-events"
            continuation.onTermination = { _ in stop.stop() }
            thread.start()
        }
    }
}

/// A flag one thread sets and another reads.
private final class Stopper: @unchecked Sendable {
    private let lock = NSLock()
    private var value = false

    var stopped: Bool { lock.withLock { value } }

    func stop() { lock.withLock { value = true } }
}
