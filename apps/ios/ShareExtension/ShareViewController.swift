// The share extension: files from any app's share sheet go to a contact.
// It cannot send them itself (an extension has a small memory budget and
// the core's profile belongs to the app), so it copies them into the App
// Group's queue with the chosen contact, and the app sends them when it
// next runs. A contact picked among the share sheet's suggestions (a
// donated INSendMessageIntent) is preselected.

import Intents
import SwiftUI
import UIKit
import UniformTypeIdentifiers

final class ShareViewController: UIViewController {
    override func viewDidLoad() {
        super.viewDidLoad()
        let suggested = (extensionContext?.intent as? INSendMessageIntent)?.conversationIdentifier
        let providers = (extensionContext?.inputItems as? [NSExtensionItem] ?? [])
            .flatMap { $0.attachments ?? [] }
        let view = ShareView(
            contacts: AppGroup.contacts, preselected: suggested, count: providers.count,
            send: { [weak self] contact in self?.queue(providers, for: contact) },
            cancel: { [weak self] in
                self?.extensionContext?.cancelRequest(withError: CocoaError(.userCancelled))
            })
        let host = UIHostingController(rootView: view)
        addChild(host)
        host.view.frame = self.view.bounds
        host.view.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        self.view.addSubview(host.view)
        host.didMove(toParent: self)
    }

    /// Moves each attachment's file into the queue, then finishes. All or
    /// nothing: if one cannot be read, nothing is queued (never fewer files
    /// than the user picked) and the share fails.
    private func queue(_ providers: [NSItemProvider], for contact: AppGroup.SharedContact) {
        Task {
            var urls: [URL] = []
            do {
                for provider in providers {
                    guard let type = provider.registeredTypeIdentifiers.first else {
                        throw CocoaError(.fileReadUnknown)
                    }
                    urls.append(try await loadFile(provider, type: type))
                }
                try ShareQueue.enqueue(contact: contact.id, urls: urls)
                removeFolders(of: urls)
                extensionContext?.completeRequest(returningItems: nil)
            } catch {
                removeFolders(of: urls)
                extensionContext?.cancelRequest(withError: error)
            }
        }
    }

    /// Removes the temporary folders `loadFile` made.
    private func removeFolders(of urls: [URL]) {
        for url in urls {
            try? FileManager.default.removeItem(at: url.deletingLastPathComponent())
        }
    }

    /// The provider's file, copied somewhere this extension owns (the
    /// provider's URL is valid only inside its callback).
    private func loadFile(_ provider: NSItemProvider, type: String) async throws -> URL {
        try await withCheckedThrowingContinuation { continuation in
            _ = provider.loadFileRepresentation(forTypeIdentifier: type) { url, error in
                guard let url else {
                    continuation.resume(throwing: error ?? CocoaError(.fileReadUnknown))
                    return
                }
                let copy = FileManager.default.temporaryDirectory
                    .appendingPathComponent(UUID().uuidString, isDirectory: true)
                do {
                    try FileManager.default.createDirectory(at: copy, withIntermediateDirectories: true)
                    let file = copy.appendingPathComponent(ShareQueue.safeName(url.lastPathComponent))
                    try FileManager.default.copyItem(at: url, to: file)
                    continuation.resume(returning: file)
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }
}

private struct ShareView: View {
    let contacts: [AppGroup.SharedContact]
    let preselected: String?
    let count: Int
    let send: (AppGroup.SharedContact) -> Void
    let cancel: () -> Void
    @State private var chosen: String?

    var body: some View {
        NavigationStack {
            List {
                Section {
                    if contacts.isEmpty {
                        Text("Pair a device in todoke first.")
                    }
                    ForEach(contacts) { contact in
                        Button {
                            chosen = contact.id
                        } label: {
                            HStack {
                                Text(contact.name)
                                Spacer()
                                if (chosen ?? preselected) == contact.id {
                                    Image(systemName: "checkmark").accessibilityLabel("Chosen")
                                }
                            }
                        }
                        .accessibilityIdentifier("share-\(contact.name)")
                    }
                } footer: {
                    Text("todoke sends them when it next opens.")
                }
            }
            .navigationTitle("Send \(count) files to…")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel", action: cancel) }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Send") {
                        if let contact = contacts.first(where: { $0.id == (chosen ?? preselected) }) { send(contact) }
                    }
                    .disabled((chosen ?? preselected).map { id in !contacts.contains { $0.id == id } } ?? true)
                }
            }
        }
    }
}
