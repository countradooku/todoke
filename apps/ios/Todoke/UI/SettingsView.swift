// Settings: who can see this device, where received files go (the Files
// app), how the key is protected, and about.

import SwiftUI
import Todoke

struct SettingsView: View {
    @Environment(AppModel.self) private var model
    @Environment(CoreService.self) private var core
    @Binding var pairingCode: Bool
    @Environment(\.openURL) private var openURL

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Text("Who can see this device").font(.headline)
                    Picker("Visibility", selection: visibility) {
                        Text("Contacts").tag(Visibility.contacts)
                        Text("Hidden").tag(Visibility.hidden)
                    }
                    .pickerStyle(.inline)
                    .labelsHidden()
                    .accessibilityIdentifier("visibility")
                    Button("Everyone, for 5 minutes (pair with a code)") { pairingCode = true }
                        .accessibilityIdentifier("everyone")
                }
                Section {
                    Text("Received files").font(.headline)
                    Text("In the Files app: On My iPhone › todoke › Received.")
                    if let files = URL(string: "shareddocuments://" + Paths.received.path) {
                        RowButton(title: "Open in Files", systemImage: "folder") { openURL(files) }
                            .accessibilityIdentifier("open-files")
                    }
                }
                Section {
                    Text("Security").font(.headline)
                    Text(protection)
                    Text(core.gated ? "Face ID or the passcode opens todoke." : "todoke opens without Face ID: the device had no passcode when todoke was set up.")
                }
                Section {
                    Text("About").font(.headline)
                    Text("Version \(Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "")")
                    if let device = model.status?.device {
                        Text("This device: \(Format.fingerprint(device))")
                            .fixedSize(horizontal: false, vertical: true)
                            .accessibilityIdentifier("this-device")
                    }
                }
            }
            .navigationTitle("Settings")
        }
    }

    private enum Visibility: Hashable {
        case contacts, hidden
    }

    private var visibility: Binding<Visibility> {
        Binding(
            get: { (model.status?.hidden ?? AppGroup.hidden) ? .hidden : .contacts },
            set: { value in Task { await model.setHidden(value == .hidden) } })
    }

    private var protection: String {
        switch model.status?.keyProtection {
        case .secureEnclave: String(localized: "Storage key protected by the Secure Enclave")
        case .keychain: String(localized: "Storage key in the Keychain (this device has no Secure Enclave)")
        case nil: "—"
        default: String(localized: "Storage key in a file")
        }
    }
}

/// A whole-row action in a list: an icon and the title in the text colour,
/// the row tappable everywhere (the form the audit reads fully).
struct RowButton: View {
    let title: LocalizedStringKey
    let systemImage: String
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 12) {
                Image(systemName: systemImage).foregroundStyle(.tint).accessibilityHidden(true)
                Text(title).fixedSize(horizontal: false, vertical: true)
                Spacer(minLength: 0)
            }
            .contentShape(.rect)
        }
        .buttonStyle(.plain)
    }
}
