// The Live Activity of the transfers in progress (the Lock Screen and the
// Dynamic Island): one activity for all of them, with the total progress.
// No file names and no contact fingerprints: a count, a direction, and the
// contact's name only when one transfer is moving.

import ActivityKit
import Foundation

struct TransferAttributes: ActivityAttributes {
    struct ContentState: Codable, Hashable {
        /// Transfers moving.
        var count: Int
        /// Bytes done and in all.
        var done: UInt64
        var total: UInt64
        /// The contact's name when one transfer is moving; empty otherwise.
        var peer: String
        /// Whether that one transfer is incoming.
        var incoming: Bool
        /// The one transfer's ID, for its Cancel button; empty otherwise.
        var transfer: String

        var fraction: Double {
            total == 0 ? 0 : min(1, Double(done) / Double(total))
        }
    }
}
