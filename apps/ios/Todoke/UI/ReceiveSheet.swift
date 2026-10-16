// The receive sheet: an offer waits for the user's decision (PROTOCOL §7.2:
// nothing is accepted before it). The sender's seal claims only what the
// session proved, a verified contact. Names are escaped by the core and
// their extension is drawn apart; programs are flagged; every decision
// button stays disabled for 700 ms each time the offer shown changes, so a
// tap aimed at what was there before cannot accept it. A resumed transfer
// can only repeat its earlier selection (§7.5). Swiping the sheet away
// hides it; the offer waits until it expires (§13).

import SwiftUI
import Todoke

/// How long the decision buttons stay disabled after an offer appears.
let armDelay: Duration = .milliseconds(700)

struct ReceiveSheet: View {
    let offer: Offer
    let accept: ([UInt32]) -> Void
    let decline: () -> Void

    @State private var armed = false
    @State private var choosing = false
    @State private var chosen: Set<UInt32> = []

    private var files: [Entry] { offer.entries.filter { !$0.directory } }
    private var folders: Int { offer.entries.filter(\.directory).count }
    private var programs: Bool { files.contains(where: Format.isProgram) }
    private var resumed: Bool { !offer.resume.isEmpty }

    var body: some View {
        NavigationStack {
            List {
                Section {
                    Label("Verified contact", systemImage: "checkmark.seal.fill")
                        .foregroundStyle(.tint)
                    Text(summary)
                    if programs {
                        HStack(alignment: .firstTextBaseline, spacing: 8) {
                            Image(systemName: "exclamationmark.triangle.fill").accessibilityHidden(true)
                            Text("Some of these are programs or scripts. Open them only if you expected them.")
                                .fixedSize(horizontal: false, vertical: true)
                        }
                        .accessibilityElement(children: .combine)
                        .accessibilityIdentifier("programs-warning")
                    }
                    if resumed {
                        Text("This transfer was interrupted: accepting it again receives what is left of your earlier choice.")
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                Section {
                    ForEach(files, id: \.id) { entry in
                        EntryRow(entry: entry, choosing: choosing, picked: chosen.contains(entry.id)) { picked in
                            if picked { chosen.insert(entry.id) } else { chosen.remove(entry.id) }
                        }
                    }
                }
            }
            .navigationTitle("From \(offer.fromName)")
            .navigationBarTitleDisplayMode(.inline)
            .safeAreaInset(edge: .bottom) { actions }
        }
        .task(id: offer.transfer) {
            armed = false
            choosing = false
            chosen = []
            try? await Task.sleep(for: armDelay)
            armed = true
        }
    }

    private var summary: String {
        var parts = [String(localized: "\(files.count) files")]
        if folders > 0 { parts.append(String(localized: "\(folders) folders")) }
        parts.append(Format.bytes(offer.totalBytes))
        return parts.joined(separator: " · ")
    }

    private var actions: some View {
        HStack(spacing: 12) {
            Button("Decline", role: .destructive, action: decline)
                .secondaryAction()
                .accessibilityIdentifier("decline")
            Spacer()
            if choosing {
                Button("Accept chosen") { accept(chosen.sorted()) }
                    .primaryAction()
                    .disabled(!armed || chosen.isEmpty)
                    .accessibilityIdentifier("accept-chosen")
            } else {
                if !resumed {
                    Button("Choose") { choosing = true }
                        .secondaryAction()
                        .accessibilityIdentifier("choose")
                }
                Button("Accept all") { accept(resumed ? offer.resume : []) }
                    .primaryAction()
                    .accessibilityIdentifier("accept-all")
            }
        }
        .disabled(!armed)
        .padding()
        .glassCard(cornerRadius: 28)
        .padding(.horizontal)
    }
}

private struct EntryRow: View {
    let entry: Entry
    let choosing: Bool
    let picked: Bool
    let pick: (Bool) -> Void

    var body: some View {
        let (stem, ext) = Format.nameParts(entry.name)
        let label = HStack(spacing: 0) {
            Text(stem).lineLimit(1).truncationMode(.middle)
            // Red and semibold for a program: bold text reads at a lower
            // contrast than regular, which this red needs.
            Text(ext)
                .foregroundStyle(Format.isProgram(entry) ? Color.warning : .primary)
                .fontWeight(Format.isProgram(entry) ? .semibold : .regular)
            Spacer(minLength: 8)
            Text(Format.bytes(entry.size)).font(.caption)
        }
        if choosing {
            // The whole row picks the file (a checkmark, as Mail and Files do).
            Button { pick(!picked) } label: {
                HStack(spacing: 12) {
                    Image(systemName: picked ? "checkmark.circle.fill" : "circle")
                        .foregroundStyle(.tint)
                        .accessibilityHidden(true)
                    label
                }
                .contentShape(.rect)
            }
            .buttonStyle(.plain)
            .accessibilityAddTraits(picked ? .isSelected : [])
            .accessibilityIdentifier("file-\(entry.name)")
        } else {
            label.accessibilityElement(children: .combine)
        }
    }
}
