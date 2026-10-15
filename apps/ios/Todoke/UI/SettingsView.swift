// Settings: who can see this device, where received files go (the Files
// app), how the key is protected, and about.

import SwiftUI
import Todoke

struct SettingsView: View {
    @Environment(AppModel.self) private var model
    @Environment(CoreService.self) private var core
    @Binding var pairingCode: Bool

    var body: some View {
        NavigationStack {
            Form {
                Section("Who can see this device") {
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
                    Text("In the Files app: On My iPhone › todoke › Received.")
                    if let files = URL(string: "shareddocuments://" + Paths.received.path) {
                        Link("Open in Files", destination: files)
                    }
                } header: {
                    Text("Received files")
                }
                Section("Security") {
                    Text(protection)
                    Text(core.gated ? "Face ID or the passcode opens todoke." : "This device has no passcode: todoke opens without unlocking.")
                        .foregroundStyle(.secondary)
                }
                Section("About") {
                    LabeledContent("Version", value: Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "")
                    if let device = model.status?.device {
                        LabeledContent("This device", value: Format.fingerprint(device))
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
