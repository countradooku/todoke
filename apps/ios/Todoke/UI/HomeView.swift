// Home: the paired devices, whether each is reachable, and Send, which opens
// the document picker; the picked documents go to the core open.

import SwiftUI
import Todoke
import UniformTypeIdentifiers

struct HomeView: View {
    @Environment(AppModel.self) private var model
    @Binding var pairing: Bool
    @State private var sendingTo: Contact?

    var body: some View {
        NavigationStack {
            Group {
                if model.contacts.isEmpty {
                    ContentUnavailableView {
                        Label("No paired devices", systemImage: "laptopcomputer.and.iphone")
                    } description: {
                        Text("Pair one to send it files.")
                    } actions: {
                        Button("Pair a device") { pairing = true }
                            .primaryAction()
                            .accessibilityIdentifier("pair-empty")
                    }
                } else {
                    ScrollView {
                        LazyVStack(spacing: 12) {
                            ForEach(model.contacts, id: \.device) { contact in
                                ContactCard(contact: contact) { sendingTo = contact }
                            }
                        }
                        .padding()
                    }
                }
            }
            .navigationTitle("Your devices")
            .toolbar {
                ToolbarItem(placement: .primaryAction) {
                    Button("Pair a device", systemImage: "qrcode") { pairing = true }
                        .accessibilityIdentifier("pair")
                }
            }
            .fileImporter(
                isPresented: Binding(get: { sendingTo != nil }, set: { if !$0 { sendingTo = nil } }),
                allowedContentTypes: [.item], allowsMultipleSelection: true
            ) { result in
                guard let contact = sendingTo, case .success(let urls) = result, !urls.isEmpty else { return }
                let documents = urls.map { Picked(url: $0, name: $0.lastPathComponent) }
                Task { await model.send(to: contact, documents: documents) }
            }
        }
    }
}

private struct ContactCard: View {
    let contact: Contact
    let send: () -> Void
    @Environment(\.dynamicTypeSize) private var size

    var body: some View {
        // Side by side, or stacked at accessibility text sizes.
        let layout = size.isAccessibilitySize
            ? AnyLayout(VStackLayout(alignment: .leading, spacing: 12))
            : AnyLayout(HStackLayout(alignment: .center, spacing: 12))
        layout {
            VStack(alignment: .leading, spacing: 4) {
                Text(contact.name)
                    .font(.headline)
                Text(Format.fingerprint(contact.device))
                    .font(.caption.monospaced())
                    .fixedSize(horizontal: false, vertical: true)
                    .accessibilityLabel("Fingerprint \(Format.fingerprint(contact.device))")
                Label(proximity, systemImage: contact.nearby ? "wifi" : (contact.available ? "globe" : "moon"))
                    .font(.caption)
            }
            if !size.isAccessibilitySize { Spacer(minLength: 8) }
            // Only a reachable device gets a button (a disabled one would
            // be text too faint to read).
            if contact.available {
                Button("Send", action: send)
                    .primaryAction()
                    .accessibilityIdentifier("send-\(contact.name)")
                    .accessibilityHint("Choose files to send to \(contact.name)")
            }
        }
        .padding()
        .frame(maxWidth: .infinity, alignment: .leading)
        // Content on a solid surface: Liquid Glass is for the controls
        // above it, and text on glass loses contrast.
        .background(.background.secondary, in: .rect(cornerRadius: 20))
        .accessibilityElement(children: .contain)
    }

    private var proximity: String {
        if contact.nearby { return String(localized: "Nearby") }
        if contact.available { return String(localized: "Through a relay") }
        return String(localized: "Not reachable")
    }
}
