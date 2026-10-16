// What the screens need from the core. CoreBackend is the real core; the UI
// tests use a scripted one (FakeBackend, debug builds only).

import Foundation
import Todoke

/// A QR code to show: its modules, row by row (true is dark), and when the
/// offer expires (Unix seconds).
struct QrCode: Equatable {
    var width: Int
    var modules: [Bool]
    var expiresAt: UInt64

    func dark(_ x: Int, _ y: Int) -> Bool { modules[y * width + x] }
}

/// A code to show while pairing by code.
struct PairingCode: Equatable {
    var code: String
    var expiresAt: UInt64
}

/// A document the user picked or shared: where it is and its name.
struct Picked: Equatable {
    var url: URL
    var name: String
}

protocol Backend: AnyObject, Sendable {
    func status() async throws -> Status
    func contacts() async throws -> [Contact]
    func transfers() async throws -> [Transfer]
    func offers() async throws -> [Offer]
    func history() async throws -> [HistoryItem]
    func clearHistory() async throws
    func showQr() async throws -> QrCode
    /// Pairs with the device whose QR was scanned; returns its fingerprint.
    func scanQr(_ text: String) async throws -> String
    func showCode() async throws -> PairingCode
    func strangers() async throws -> [Stranger]
    func enterCode(_ code: String, stranger: String) async throws -> String
    func stopPairing() async throws
    func setHidden(_ hidden: Bool) async throws
    /// The app entered the background or left it (PROTOCOL §10.3: no
    /// listener, no advertising, no relay presence there).
    func setBackground(_ background: Bool) async throws
    /// Sends `documents` to `contact`; returns the transfer's ID.
    func send(to contact: String, documents: [Picked]) async throws -> String
    /// Sends files by path (the share queue, inside the App Group).
    func send(to contact: String, paths: [String]) async throws -> String
    func accept(_ transfer: String, files: [UInt32]) async throws
    func decline(_ transfer: String) async throws
    func cancel(_ transfer: String) async throws
    /// Whether this iPhone can be pointed at now (PROTOCOL §10.4): the
    /// configurations it ranges with (bit 1, Apple peer ranging), or none.
    func setRangingReady(_ configs: UInt8?) async throws
    /// Points at nearby iPhones with these prepared sessions' tokens.
    func pointStartPeer(tokens: [Data]) async throws
    func pointStop() async throws
    /// Ranges with `contact`, which points at this iPhone, with `token`.
    func acceptPeerRanging(contact: String, sessionId: UInt32, token: Data) async throws
    func refuseRanging(contact: String, sessionId: UInt32) async throws
    /// The core's events until it stops.
    func events() -> AsyncStream<CoreEvent>
}
