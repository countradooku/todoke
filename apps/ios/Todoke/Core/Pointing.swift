// Point to share between iPhones (PROTOCOL §10.4) with Nearby Interaction.
// While the app is on screen and the iPhone measures precise distance, it
// can be pointed at: contacts in sessions learn so, and a contact that
// points gets a fresh Nearby Interaction session of ours for each ranging
// (its discovery token goes to the contact inside the session). Pointing
// prepares a few sessions (each token serves one contact), ranges with
// every nearby contact that accepts, and keeps where each one is. Ranging
// is a hint for the screen only: sending still needs the user's choice
// and the receiver's consent. Nothing ranges in the background (iOS
// suspends the sessions), and no token is logged or kept after its
// ranging.

import Foundation
import NearbyInteraction
import Observation
import Todoke

/// Where a contact is, as ranging last measured it.
struct Bearing: Equatable {
    var meters: Float?
    /// Degrees off straight ahead (negative: to the left).
    var degrees: Float?
}

@MainActor
@Observable
final class Pointing {
    /// The contacts ranged now, by fingerprint.
    private(set) var bearings: [String: Bearing] = [:]
    /// Whether this iPhone can point and be pointed at now.
    private(set) var ready = false
    private(set) var active = false

    @ObservationIgnored private let backend: Backend
    /// Sessions prepared for pointing, by their archived token.
    @ObservationIgnored private var prepared: [Data: Ranger] = [:]
    /// Sessions ranging, by ranging session ID.
    @ObservationIgnored private var running: [UInt32: Ranger] = [:]
    @ObservationIgnored private var listening: Task<Void, Never>?

    /// The most rangings at once.
    private static let maxTargets = 4

    static var supported: Bool { NISession.deviceCapabilities.supportsPreciseDistanceMeasurement }

    init(backend: Backend) {
        self.backend = backend
    }

    /// The app came on screen, or left it.
    func setForeground(_ foreground: Bool) async {
        if foreground, listening == nil {
            let events = backend.events()
            listening = Task { [weak self] in
                for await event in events { self?.handle(event) }
            }
        }
        ready = foreground && Self.supported
        try? await backend.setRangingReady(ready ? 2 : nil)
        if !ready {
            await stop()
            listening?.cancel()
            listening = nil
        }
    }

    /// Points at up to `nearby` contacts.
    func start(nearby: Int) async {
        guard ready else { return }
        await stop()
        var tokens: [Data] = []
        for _ in 0..<min(max(nearby, 1), Self.maxTargets) {
            let ranger = Ranger { [weak self] contact, bearing in self?.bearings[contact] = bearing }
            guard let token = ranger.token else { continue }
            prepared[token] = ranger
            tokens.append(token)
        }
        do {
            try await backend.pointStartPeer(tokens: tokens)
            active = true
        } catch {
            prepared.values.forEach { $0.invalidate() }
            prepared = [:]
        }
    }

    func stop() async {
        if active { try? await backend.pointStop() }
        active = false
        for ranger in Array(running.values) + Array(prepared.values) { ranger.invalidate() }
        running = [:]
        prepared = [:]
        bearings = [:]
    }

    private func handle(_ event: CoreEvent) {
        switch event {
        case .peerPointTarget(let ranging):
            guard let local = ranging.localToken, let ranger = prepared.removeValue(forKey: local) else { return }
            ranger.contact = ranging.contact
            running[ranging.sessionId] = ranger
            ranger.run(peerToken: ranging.peerToken)
        case .peerRangingRequested(let ranging):
            Task { await answer(ranging) }
        case .rangingStopped(let contact, let sessionId):
            running.removeValue(forKey: sessionId)?.invalidate()
            bearings[contact] = nil
        default:
            break
        }
    }

    /// A contact points at this iPhone: a fresh session answers it.
    private func answer(_ ranging: PeerRangingInfo) async {
        let ranger = Ranger { _, _ in }
        guard ready, let token = ranger.token else {
            ranger.invalidate()
            try? await backend.refuseRanging(contact: ranging.contact, sessionId: ranging.sessionId)
            return
        }
        do {
            try await backend.acceptPeerRanging(contact: ranging.contact, sessionId: ranging.sessionId, token: token)
            ranger.contact = ranging.contact
            running[ranging.sessionId] = ranger
            ranger.run(peerToken: ranging.peerToken)
        } catch {
            ranger.invalidate()
        }
    }
}

/// One Nearby Interaction session, for one ranging.
final class Ranger: NSObject, NISessionDelegate {
    private let session = NISession()
    /// The contact it ranges with, once known.
    var contact: String?
    private let update: @MainActor (String, Bearing) -> Void

    init(update: @escaping @MainActor (String, Bearing) -> Void) {
        self.update = update
        super.init()
        session.delegate = self
    }

    /// This session's discovery token, archived for the core.
    var token: Data? {
        session.discoveryToken.flatMap {
            try? NSKeyedArchiver.archivedData(withRootObject: $0, requiringSecureCoding: true)
        }
    }

    /// Ranges with the contact's archived token.
    func run(peerToken: Data) {
        guard let token = try? NSKeyedUnarchiver.unarchivedObject(ofClass: NIDiscoveryToken.self, from: peerToken)
        else { return }
        session.run(NINearbyPeerConfiguration(peerToken: token))
    }

    func invalidate() {
        session.invalidate()
    }

    func session(_ session: NISession, didUpdate nearbyObjects: [NINearbyObject]) {
        guard let object = nearbyObjects.first, let contact else { return }
        // Azimuth from the direction (x right, z toward the user).
        let degrees = object.direction.map { atan2($0.x, -$0.z) * 180 / .pi }
        let bearing = Bearing(meters: object.distance, degrees: degrees)
        Task { @MainActor in update(contact, bearing) }
    }
}
