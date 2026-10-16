// Queues files for a contact in the App Group, for the app to send when it
// runs: one folder per request, the files moved or written in (names
// reduced to their last path component, made unique), and the request
// written last. Everything is protected while the device is locked, unless
// already open (a transfer under way keeps reading).

import Foundation

enum ShareQueue {
    /// Queues `files` (name and bytes) for the contact with keyed ID
    /// `contact`.
    static func enqueue(contact: String, files: [(String, Data)]) throws {
        let folder = try newFolder()
        var names: [String] = []
        for (name, data) in files {
            let unique = uniqueName(safeName(name), taken: names)
            try data.write(to: folder.appendingPathComponent(unique), options: [.atomic, .completeFileProtectionUnlessOpen])
            names.append(unique)
        }
        try finish(folder: folder, contact: contact, names: names)
    }

    /// Queues files this process owns (moved in, not copied). On an error
    /// the request's folder is removed.
    static func enqueue(contact: String, urls: [URL]) throws {
        let folder = try newFolder()
        do {
            var names: [String] = []
            for url in urls {
                let unique = uniqueName(safeName(url.lastPathComponent), taken: names)
                let file = folder.appendingPathComponent(unique)
                try FileManager.default.moveItem(at: url, to: file)
                try FileManager.default.setAttributes(
                    [.protectionKey: FileProtectionType.completeUnlessOpen], ofItemAtPath: file.path)
                names.append(unique)
            }
            try finish(folder: folder, contact: contact, names: names)
        } catch {
            try? FileManager.default.removeItem(at: folder)
            throw error
        }
    }

    private static func newFolder() throws -> URL {
        var outbox = AppGroup.outbox
        try FileManager.default.createDirectory(at: outbox, withIntermediateDirectories: true)
        // Queued files wait for one send: never in a backup.
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try outbox.setResourceValues(values)
        let folder = outbox.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        return folder
    }

    private static func finish(folder: URL, contact: String, names: [String]) throws {
        let request = AppGroup.QueuedShare(contact: contact, names: names, created: Date())
        try JSONEncoder().encode(request).write(
            to: folder.appendingPathComponent(AppGroup.requestFile),
            options: [.atomic, .completeFileProtectionUnlessOpen])
        CrossProcess.post(CrossProcess.outbox)
    }

    /// The last path component, never empty, never the request's own name.
    static func safeName(_ name: String) -> String {
        let last = (name as NSString).lastPathComponent.replacingOccurrences(of: "/", with: "_")
        if last.isEmpty || last == "." || last == ".." || last == AppGroup.requestFile || last == "sent.json" {
            return "file"
        }
        return last
    }

    static func uniqueName(_ name: String, taken: [String]) -> String {
        guard taken.contains(name) else { return name }
        let stem = (name as NSString).deletingPathExtension
        let ext = (name as NSString).pathExtension
        for n in 2... {
            let candidate = ext.isEmpty ? "\(stem) \(n)" : "\(stem) \(n).\(ext)"
            if !taken.contains(candidate) { return candidate }
        }
        return name
    }
}
