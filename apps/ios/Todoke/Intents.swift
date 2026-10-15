// Shortcuts and the Action button: change visibility (the shared intent),
// open pairing, and send files to a contact. Sending queues the files like
// the share extension does and opens the app, which sends them (the core
// runs only in the app, after it unlocks).

import AppIntents
import Foundation

struct ContactEntity: AppEntity {
    static let typeDisplayRepresentation: TypeDisplayRepresentation = "Contact"
    static let defaultQuery = ContactQuery()

    /// The contact's keyed ID (never its fingerprint).
    var id: String
    var name: String

    var displayRepresentation: DisplayRepresentation { DisplayRepresentation(title: "\(name)") }
}

struct ContactQuery: EntityQuery {
    func entities(for identifiers: [String]) async throws -> [ContactEntity] {
        AppGroup.contacts.filter { identifiers.contains($0.id) }.map { ContactEntity(id: $0.id, name: $0.name) }
    }

    func suggestedEntities() async throws -> [ContactEntity] {
        AppGroup.contacts.map { ContactEntity(id: $0.id, name: $0.name) }
    }
}

struct SendFilesIntent: AppIntent {
    static let title: LocalizedStringResource = "Send files with todoke"
    static let description = IntentDescription("Sends files to one of your paired devices.")
    static let openAppWhenRun = true

    @Parameter(title: "Files")
    var files: [IntentFile]

    @Parameter(title: "To")
    var contact: ContactEntity

    func perform() async throws -> some IntentResult {
        try ShareQueue.enqueue(contact: contact.id, files: files.map { ($0.filename, $0.data) })
        return .result()
    }
}

struct OpenPairingIntent: AppIntent {
    static let title: LocalizedStringResource = "Pair a device with todoke"
    static let description = IntentDescription("Opens todoke's pairing screen.")
    static let openAppWhenRun = true

    func perform() async throws -> some IntentResult {
        UserDefaults.standard.set(true, forKey: "open-pairing")
        return .result()
    }
}

struct TodokeShortcuts: AppShortcutsProvider {
    static var appShortcuts: [AppShortcut] {
        AppShortcut(intent: SendFilesIntent(), phrases: ["Send files with \(.applicationName)"],
                    shortTitle: "Send files", systemImageName: "paperplane")
        AppShortcut(intent: ToggleVisibilityIntent(), phrases: ["Toggle \(.applicationName) visibility"],
                    shortTitle: "Visibility", systemImageName: "eye")
        AppShortcut(intent: OpenPairingIntent(), phrases: ["Pair a device with \(.applicationName)"],
                    shortTitle: "Pair a device", systemImageName: "qrcode")
    }
}
