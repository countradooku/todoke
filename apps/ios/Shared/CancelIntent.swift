// Cancel from the Live Activity's button. A Live Activity intent runs in
// the app's process, which has the core: it records the request, and the
// app cancels at its next read (within two seconds while it runs).

import AppIntents
import Foundation

struct CancelTransferIntent: LiveActivityIntent {
    static let title: LocalizedStringResource = "Cancel the transfer"

    @Parameter(title: "Transfer")
    var transfer: String

    init() {}

    init(transfer: String) {
        self.transfer = transfer
    }

    func perform() async throws -> some IntentResult {
        CancelRequests.add(transfer)
        return .result()
    }
}

/// Transfers the user asked to cancel from outside the app's screens.
enum CancelRequests {
    private static let key = "cancel-requests"

    static func add(_ transfer: String) {
        var pending = AppGroup.defaults.stringArray(forKey: key) ?? []
        if !pending.contains(transfer) { pending.append(transfer) }
        AppGroup.defaults.set(Array(pending.suffix(16)), forKey: key)
    }

    /// The requests, emptied.
    static func take() -> [String] {
        let pending = AppGroup.defaults.stringArray(forKey: key) ?? []
        AppGroup.defaults.removeObject(forKey: key)
        return pending
    }
}
