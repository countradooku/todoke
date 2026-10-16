// What the app and its extensions share, in the App Group container: the
// visibility the widget and the Control Center control show and change,
// the contacts the share extension offers (names and opaque IDs), and the
// share queue. Nothing secret: the storage key stays in the app's own
// Keychain group, and the core's state in the app's own container.

import CryptoKit
import Foundation

enum AppGroup {
    static let identifier = "group.org.todoke.ios"

    /// The shared settings; standard defaults when the group is missing
    /// (an unsigned build), so nothing crashes.
    static var defaults: UserDefaults {
        UserDefaults(suiteName: identifier) ?? .standard
    }

    /// The shared container, or the app's own caches without one.
    static var container: URL {
        FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: identifier)
            ?? FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0]
    }

    /// Files the share extension queued, one folder per request.
    static var outbox: URL {
        container.appendingPathComponent("Outbox", isDirectory: true)
    }

    // MARK: Visibility

    private static let hiddenKey = "hidden"

    /// Hidden: nothing paired is advertised (the core's `set_hidden`).
    static var hidden: Bool {
        get { defaults.bool(forKey: hiddenKey) }
        set {
            defaults.set(newValue, forKey: hiddenKey)
            CrossProcess.post(CrossProcess.visibility)
        }
    }

    // MARK: Contacts for the share extension

    /// A contact as the share extension shows it.
    struct SharedContact: Codable, Hashable, Identifiable {
        /// The contact's keyed ID (`shortcutID`), never its fingerprint.
        var id: String
        var name: String
        var available: Bool
    }

    private static let contactsKey = "contacts"

    static var contacts: [SharedContact] {
        get {
            guard let data = defaults.data(forKey: contactsKey) else { return [] }
            return (try? JSONDecoder().decode([SharedContact].self, from: data)) ?? []
        }
        set { defaults.set(try? JSONEncoder().encode(newValue), forKey: contactsKey) }
    }

    /// A contact's ID outside the app (the share sheet's suggestions, the
    /// share queue): HMAC-SHA-256 of its fingerprint under a random key of
    /// this install, 128 bits, so the system's intent store and the shared
    /// container never hold a fingerprint.
    static func shortcutID(for device: String) -> String {
        let key = SymmetricKey(data: shortcutKey())
        let mac = HMAC<SHA256>.authenticationCode(for: Data(device.utf8), using: key)
        return Data(mac).prefix(16).map { String(format: "%02x", $0) }.joined()
    }

    private static let shortcutKeyName = "shortcut-key"

    private static func shortcutKey() -> Data {
        if let key = defaults.data(forKey: shortcutKeyName), key.count == 32 { return key }
        var key = Data(count: 32)
        let status = key.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
        precondition(status == errSecSuccess, "no randomness")
        defaults.set(key, forKey: shortcutKeyName)
        return key
    }

    // MARK: Share queue

    /// One queued share: the files (copied into its folder) and the
    /// contact chosen, by keyed ID.
    struct QueuedShare: Codable {
        var contact: String
        var names: [String]
        var created: Date
    }

    static let requestFile = "request.json"
}

/// Cross-process notifications (no payload): one process changed a shared
/// value, the others read it again.
enum CrossProcess {
    static let visibility = "org.todoke.ios.visibility"
    static let outbox = "org.todoke.ios.outbox"

    static func post(_ name: String) {
        CFNotificationCenterPostNotification(
            CFNotificationCenterGetDarwinNotifyCenter(), CFNotificationName(name as CFString), nil, nil, true)
    }
}
