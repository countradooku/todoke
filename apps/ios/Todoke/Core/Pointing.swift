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
    /// Whether this iPhone measures precise distance (tests choose).
    @ObservationIgnored private let capable: Bool
    /// Sessions prepared for pointing, by their archived token.
    @ObservationIgnored private var prepared: [Data: Ranger] = [:]
    /// Sessions ranging, by ranging session ID.
    @ObservationIgnored private var running: [UInt32: Ranger] = [:]
    @ObservationIgnored private var listening: Task<Void, Never>?

    /// The most rangings at once.
    private static let maxTargets = 4

    nonisolated static var supported: Bool { NISession.deviceCapabilities.supportsPreciseDistanceMeasurement }

    init(backend: Backend, capable: Bool = Pointing.supported) {
        self.backend = backend
        self.capable = capable
    }

    /// The app came on screen, or left it.
    func setForeground(_ foreground: Bool) async {
        if foreground, listening == nil {
            let events = backend.events()
            listening = Task { [weak self] in
                for await event in events { self?.handle(event) }
            }
        }
        ready = foreground && capable
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
            let ranger = makeRanger()
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

    /// A session for one ranging, which reports where its contact is and
    /// when it ended on its own.
    private func makeRanger(answering: Bool = false) -> Ranger {
        let ranger = Ranger(
            update: { [weak self] contact, bearing in
                guard !answering else { return }
                self?.bearings[contact] = bearing
            },
            ended: { [weak self] ranger in self?.ended(ranger) })
        ranger.answering = answering
        return ranger
    }

    /// iOS invalidated a session, or its peer left for good: the ranging
    /// is over here. One answered is stopped in the core too.
    private func ended(_ ranger: Ranger) {
        if let (token, _) = prepared.first(where: { $0.value === ranger }) {
            prepared[token] = nil
            return
        }
        guard let (sessionId, _) = running.first(where: { $0.value === ranger }) else { return }
        running[sessionId] = nil
        guard let contact = ranger.contact else { return }
        bearings[contact] = nil
        if ranger.answering {
            Task { try? await backend.refuseRanging(contact: contact, sessionId: sessionId) }
        }
    }

    /// A contact points at this iPhone: a fresh session answers it. It is
    /// kept as running before the core is told, so a stop that comes
    /// meanwhile finds it.
    private func answer(_ ranging: PeerRangingInfo) async {
        let ranger = makeRanger(answering: true)
        guard ready, running[ranging.sessionId] == nil, let token = ranger.token else {
            ranger.invalidate()
            try? await backend.refuseRanging(contact: ranging.contact, sessionId: ranging.sessionId)
            return
        }
        ranger.contact = ranging.contact
        running[ranging.sessionId] = ranger
        do {
            try await backend.acceptPeerRanging(contact: ranging.contact, sessionId: ranging.sessionId, token: token)
        } catch {
            if running[ranging.sessionId] === ranger { running[ranging.sessionId] = nil }
            ranger.invalidate()
            return
        }
        // Stopped (or replaced) while the core was told: nothing to run.
        guard running[ranging.sessionId] === ranger else {
            ranger.invalidate()
            return
        }
        ranger.run(peerToken: ranging.peerToken)
    }
}

/// One Nearby Interaction session, for one ranging. Its delegate calls
/// come on the main queue (the session's default).
final class Ranger: NSObject, NISessionDelegate {
    private let session = NISession()
    /// The contact it ranges with, once known.
    var contact: String?
    /// Whether it answers a contact's pointing (not points itself).
    var answering = false
    private var configuration: NINearbyPeerConfiguration?
    private let update: @MainActor (String, Bearing) -> Void
    private let ended: @MainActor (Ranger) -> Void

    init(update: @escaping @MainActor (String, Bearing) -> Void, ended: @escaping @MainActor (Ranger) -> Void) {
        self.update = update
        self.ended = ended
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
        let configuration = NINearbyPeerConfiguration(peerToken: token)
        self.configuration = configuration
        session.run(configuration)
    }

    func invalidate() {
        configuration = nil
        session.invalidate()
    }

    func session(_ session: NISession, didInvalidateWith error: Error) {
        configuration = nil
        Task { @MainActor in ended(self) }
    }

    /// Back on screen: a suspended session runs again only when asked.
    func sessionSuspensionEnded(_ session: NISession) {
        if let configuration { session.run(configuration) }
    }

    func session(_ session: NISession, didRemove nearbyObjects: [NINearbyObject], reason: NINearbyObject.RemovalReason) {
        switch reason {
        case .timeout:
            // Out of range for now: ranging resumes if it comes back.
            if let configuration { session.run(configuration) }
        case .peerEnded:
            invalidate()
            Task { @MainActor in ended(self) }
        @unknown default:
            break
        }
    }

    func session(_ session: NISession, didUpdate nearbyObjects: [NINearbyObject]) {
        guard let object = nearbyObjects.first, let contact else { return }
        // Azimuth from the direction (x right, z toward the user).
        let degrees = object.direction.map { atan2($0.x, -$0.z) * 180 / .pi }
        let bearing = Bearing(meters: object.distance, degrees: degrees)
        Task { @MainActor in update(contact, bearing) }
    }
}
