// Direct Wi-Fi links for the core (PROTOCOL §10.2), iPhone side: joining a
// Wi-Fi Direct group (Android, Windows) or a hotspot (Android) with exactly
// the credentials the host offered inside the session. NEHotspotConfiguration
// with `joinOnce`: the network is never saved, the system asks the user
// first, and it goes when the link is released, when the app has been in
// the background for 15 seconds, or when the device sleeps. iOS hosts
// nothing (no API lets an app run a hotspot or a group).
//
// The joined network has no internet, so iOS keeps cellular as the default
// route: the core's sockets for the link are bound to the Wi-Fi interface
// (IP_BOUND_IF), and the host's address is that interface's default
// gateway, which the core reads from the routing table (iOS has no API
// naming it). The core calls these on its own threads; they block while
// the system joins.

import Darwin
import Foundation
import NetworkExtension
import Todoke

final class AppleLinks: WifiLinks, @unchecked Sendable {
    private let lock = NSLock()
    private var leases: [UInt64: Joined] = [:]
    private var nextID: UInt64 = 0
    private var allowed = false

    private struct Joined {
        let ssid: String
        let interface: UInt32
    }

    /// Links are set up only while the app shows, or a transfer the user
    /// started runs in the background (a joined network outlives neither).
    func setAllowed(_ allowed: Bool) {
        lock.withLock { self.allowed = allowed }
    }

    func abilities() -> LinkAbilities {
        guard lock.withLock({ allowed }) else { return LinkAbilities(host: [], join: [], joinSecurity: []) }
        // WPA3-only networks are not documented for NEHotspotConfiguration;
        // a transition network takes WPA2 as well.
        return LinkAbilities(host: [], join: [.wifiDirect, .hotspot], joinSecurity: [.wpa3Transition, .wpa2])
    }

    func host(request: LinkRequest) throws -> LinkLease {
        throw LinkError.failed(message: "iOS hosts no direct link")
    }

    func join(request: LinkRequest) throws -> LinkLease {
        guard lock.withLock({ allowed }) else { throw LinkError.failed(message: "not now: the app is not in use") }
        guard request.kind == .wifiDirect || request.kind == .hotspot else {
            throw LinkError.failed(message: "this iPhone joins no Wi-Fi Aware data path")
        }
        guard request.security == .wpa2 || request.security == .wpa3Transition,
              let passphrase = String(data: request.secret, encoding: .ascii)
        else { throw LinkError.failed(message: "not a security this iPhone joins") }
        let within = Double(request.withinMs > 0 ? request.withinMs : 30_000) / 1000
        let deadline = Date().addingTimeInterval(within)
        let configuration = NEHotspotConfiguration(ssid: request.ssid, passphrase: passphrase, isWEP: false)
        configuration.joinOnce = true
        let applied = DispatchSemaphore(value: 0)
        nonisolated(unsafe) var failure: Error?
        NEHotspotConfigurationManager.shared.apply(configuration) { error in
            failure = error
            applied.signal()
        }
        guard applied.wait(timeout: .now() + within) == .success else {
            remove(request.ssid)
            throw LinkError.failed(message: "joining took too long")
        }
        if let error = failure as NSError?,
           !(error.domain == NEHotspotConfigurationErrorDomain
               && error.code == NEHotspotConfigurationError.alreadyAssociated.rawValue) {
            remove(request.ssid)
            throw LinkError.failed(message: error.localizedDescription)
        }
        // Applied is not joined: wait until this is the current network and
        // the Wi-Fi interface has its address.
        while Date() < deadline {
            if currentSSID() == request.ssid, case let (interface, address)? = wifiAddress() {
                let id = lock.withLock { () -> UInt64 in
                    nextID += 1
                    leases[nextID] = Joined(ssid: request.ssid, interface: interface)
                    return nextID
                }
                return LinkLease(
                    id: id, local: address, host: nil, interface: interface, bindSockets: true, scopes: [])
            }
            Thread.sleep(forTimeInterval: 0.3)
        }
        remove(request.ssid)
        throw LinkError.failed(message: "the network did not come up")
    }

    func bindSocket(lease: UInt64, socket: Int64) throws {
        guard var interface = lock.withLock({ leases[lease]?.interface }) else { throw LinkError.closed }
        let size = socklen_t(MemoryLayout<UInt32>.size)
        let fd = Int32(truncatingIfNeeded: socket)
        // IPv4 or IPv6, whichever the socket is.
        if setsockopt(fd, IPPROTO_IP, IP_BOUND_IF, &interface, size) != 0,
           setsockopt(fd, IPPROTO_IPV6, IPV6_BOUND_IF, &interface, size) != 0 {
            throw LinkError.failed(message: "the socket could not be bound to Wi-Fi")
        }
    }

    func release(lease: UInt64) {
        if let joined = lock.withLock({ leases.removeValue(forKey: lease) }) {
            remove(joined.ssid)
        }
    }

    private func remove(_ ssid: String) {
        NEHotspotConfigurationManager.shared.removeConfiguration(forSSID: ssid)
    }

    /// The network the iPhone is on (readable for networks this app
    /// configured).
    private func currentSSID() -> String? {
        let done = DispatchSemaphore(value: 0)
        nonisolated(unsafe) var ssid: String?
        NEHotspotNetwork.fetchCurrent { network in
            ssid = network?.ssid
            done.signal()
        }
        _ = done.wait(timeout: .now() + 2)
        return ssid
    }

    /// The Wi-Fi interface's index and IPv4 address, once it has one.
    private func wifiAddress() -> (UInt32, String)? {
        let interface = if_nametoindex("en0")
        guard interface != 0 else { return nil }
        var list: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&list) == 0, let first = list else { return nil }
        defer { freeifaddrs(list) }
        for entry in sequence(first: first, next: { $0.pointee.ifa_next }) {
            guard let address = entry.pointee.ifa_addr, address.pointee.sa_family == UInt8(AF_INET),
                  if_nametoindex(entry.pointee.ifa_name) == interface
            else { continue }
            var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            guard getnameinfo(address, socklen_t(address.pointee.sa_len), &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST) == 0
            else { continue }
            return (interface, String(cString: host))
        }
        return nil
    }
}
