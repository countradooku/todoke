// Point to share (PROTOCOL §10.4): while the sheet shows, this iPhone
// ranges with the nearby contacts that can be pointed at and lists them by
// how straight ahead each is; the one pointed at comes first and is marked.
// Choosing one opens the file picker for it, as its Send button does: the
// ranging only suggests, the user still picks.

import SwiftUI
import Todoke

struct PointSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let choose: (Contact) -> Void

    /// How far off straight ahead (degrees) still counts as pointed at.
    private static let ahead: Float = 20

    var body: some View {
        NavigationStack {
            List {
                if ranked.isEmpty {
                    Text("Looking for nearby iPhones with todoke open…")
                        .foregroundStyle(.secondary)
                } else {
                    Text("Point at the device to send to. The closest to straight ahead comes first.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
                ForEach(Array(ranked.enumerated()), id: \.element.0.device) { index, entry in
                    let (contact, bearing) = entry
                    let pointed = index == 0 && abs(bearing.degrees ?? 180) <= Self.ahead
                    Button {
                        choose(contact)
                    } label: {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(contact.name)
                                .font(pointed ? .title3.bold() : .body)
                            Text(details(bearing, pointed: pointed))
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                    .accessibilityHint("Choose files to send to \(contact.name)")
                }
            }
            .navigationTitle("Point to share")
            .toolbar {
                ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } }
            }
        }
        .task {
            let nearby = model.contacts.filter { $0.nearby || $0.connected }.count
            await model.pointing.start(nearby: nearby)
        }
        .onDisappear {
            let pointing = model.pointing
            Task { await pointing.stop() }
        }
    }

    /// The contacts ranged now, closest to straight ahead first.
    private var ranked: [(Contact, Bearing)] {
        model.contacts
            .compactMap { contact in model.pointing.bearings[contact.device].map { (contact, $0) } }
            .sorted { abs($0.1.degrees ?? 180) < abs($1.1.degrees ?? 180) }
    }

    private func details(_ bearing: Bearing, pointed: Bool) -> String {
        var parts: [String] = []
        if let meters = bearing.meters {
            parts.append(String(localized: "\(meters, format: .number.precision(.fractionLength(1))) m"))
        }
        if pointed { parts.append(String(localized: "Straight ahead")) }
        return parts.joined(separator: " · ")
    }
}
