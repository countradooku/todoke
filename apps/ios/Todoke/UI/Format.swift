// Display helpers. Names come escaped by the core; the program lists are
// the desktop app's (todoke-desktop), so a program is flagged the same
// everywhere.

import Foundation
import Todoke

enum Format {
    static func bytes(_ count: UInt64) -> String {
        ByteCountFormatter.string(fromByteCount: Int64(clamping: count), countStyle: .file)
    }

    /// A fingerprint as four groups of four, upper case (what people compare).
    static func fingerprint(_ device: String) -> String {
        let short = device.prefix(16).uppercased()
        return stride(from: 0, to: short.count, by: 4).map { offset -> String in
            let start = short.index(short.startIndex, offsetBy: offset)
            return String(short[start..<short.index(start, offsetBy: min(4, short.count - offset))])
        }.joined(separator: " ")
    }

    /// The stem and the extension (with its dot), drawn apart.
    static func nameParts(_ name: String) -> (String, String) {
        guard let dot = name.lastIndex(of: "."), dot != name.startIndex else { return (name, "") }
        return (String(name[..<dot]), String(name[dot...]))
    }

    private static let programs: Set<String> = [
        "exe", "msi", "bat", "cmd", "com", "scr", "pif", "ps1", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta",
        "cpl", "msc", "lnk", "reg", "jar", "app", "pkg", "dmg", "command", "sh", "bash", "zsh", "csh", "ksh",
        "py", "pl", "rb", "php", "apk", "aab", "deb", "rpm", "appimage", "run", "bin", "elf", "so", "dll",
        "dylib", "scpt", "applescript", "workflow", "action", "terminal", "url", "webloc", "desktop", "ipa",
    ]

    private static let programTypes: Set<String> = [
        "application/x-msdownload", "application/x-msi", "application/x-sh", "application/x-executable",
        "application/vnd.android.package-archive", "application/x-apple-diskimage", "application/java-archive",
    ]

    static func isProgram(_ entry: Entry) -> Bool {
        let ext = nameParts(entry.name).1.dropFirst().lowercased()
        return programs.contains(ext) || programTypes.contains(entry.mime.lowercased())
    }

    static func state(_ state: TransferState) -> String {
        switch state {
        case .offered: String(localized: "Offered")
        case .awaitingDecision: String(localized: "Waiting for a decision")
        case .accepted, .transferring: String(localized: "Transferring")
        case .interrupted: String(localized: "Interrupted; resumes when the device is back")
        case .received: String(localized: "Received")
        case .delivered: String(localized: "Delivered, receipt verified")
        case .unconfirmed: String(localized: "Sent, no receipt")
        case .rejected: String(localized: "Declined")
        case .cancelled: String(localized: "Cancelled")
        case .failed: String(localized: "Failed")
        }
    }
}
