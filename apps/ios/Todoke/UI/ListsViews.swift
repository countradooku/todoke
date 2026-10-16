// Transfers (both ways, with progress and Cancel) and History (searchable,
// with hashes and receipts, cleared on request).

import SwiftUI
import Todoke

struct TransfersView: View {
    @Environment(AppModel.self) private var model

    private static let cancellable: Set<TransferState> = [.offered, .awaitingDecision, .accepted, .transferring, .interrupted]

    var body: some View {
        NavigationStack {
            Group {
                if model.transfers.isEmpty {
                    ContentUnavailableView("Nothing moving", systemImage: "arrow.up.arrow.down",
                                           description: Text("Transfers in both directions show here."))
                } else {
                    List(model.transfers, id: \.id) { transfer in
                        TransferRow(transfer: transfer, peer: peer(of: transfer),
                                    cancellable: Self.cancellable.contains(transfer.state)) {
                            Task { await model.cancel(transfer) }
                        }
                    }
                }
            }
            .navigationTitle("Transfers")
        }
    }

    private func peer(of transfer: Transfer) -> String {
        model.contacts.first { $0.device == transfer.peer }?.name ?? Format.fingerprint(transfer.peer)
    }
}

private struct TransferRow: View {
    let transfer: Transfer
    let peer: String
    let cancellable: Bool
    let cancel: () -> Void
    @Environment(\.dynamicTypeSize) private var size

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            // Side by side, or stacked at accessibility text sizes.
            let layout = size.isAccessibilitySize ? AnyLayout(VStackLayout(alignment: .leading)) : AnyLayout(HStackLayout())
            layout {
                HStack(alignment: .firstTextBaseline, spacing: 6) {
                    Image(systemName: transfer.way == .incoming ? "arrow.down.circle" : "arrow.up.circle")
                        .accessibilityHidden(true)
                    Text(transfer.way == .incoming ? "From \(peer)" : "To \(peer)")
                        .fixedSize(horizontal: false, vertical: true)
                }
                if !size.isAccessibilitySize { Spacer() }
                if cancellable {
                    Button("Cancel", action: cancel)
                        .buttonStyle(.bordered)
                        .tint(.primary)
                        .accessibilityIdentifier("cancel-\(transfer.id.prefix(4))")
                }
            }
            // The bar is drawn; VoiceOver reads the line below it.
            ProgressView(value: fraction)
                .accessibilityHidden(true)
            Text("\(Int(fraction * 100))% · \(Format.bytes(transfer.bytesDone)) of \(Format.bytes(transfer.bytesTotal)) · \(Format.state(transfer.state))")
                .font(.caption)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(.vertical, 4)
    }

    private var fraction: Double {
        transfer.bytesTotal == 0 ? 0 : Double(transfer.bytesDone) / Double(transfer.bytesTotal)
    }
}

struct HistoryView: View {
    @Environment(AppModel.self) private var model
    @State private var search = ""
    @State private var confirming = false

    var body: some View {
        NavigationStack {
            Group {
                if model.history.isEmpty {
                    ContentUnavailableView("No history", systemImage: "clock",
                                           description: Text("Finished transfers stay here for 30 days."))
                } else {
                    List {
                        ForEach(filtered, id: \.transfer) { item in
                        VStack(alignment: .leading, spacing: 4) {
                            Text(item.names.joined(separator: ", ")).font(.headline)
                                .fixedSize(horizontal: false, vertical: true)
                            Text("\(Format.state(item.state)) · \(Format.bytes(item.bytes))")
                                .font(.caption)
                            Text(item.manifestHash.prefix(16)).font(.caption.monospaced())
                                .fixedSize(horizontal: false, vertical: true)
                                .accessibilityLabel("Manifest hash \(item.manifestHash.prefix(16))")
                        }
                        .accessibilityElement(children: .combine)
                        }
                        // The confirmation says it is destructive.
                        RowButton(title: "Clear the history", systemImage: "trash") { confirming = true }
                            .accessibilityIdentifier("clear-history")
                    }
                    .searchable(text: $search)
                }
            }
            .navigationTitle("History")
            .confirmationDialog("Clear the history?", isPresented: $confirming, titleVisibility: .visible) {
                Button("Clear", role: .destructive) { Task { await model.clearHistory() } }
                    .accessibilityIdentifier("confirm-clear")
            }
        }
    }

    private var filtered: [HistoryItem] {
        guard !search.isEmpty else { return model.history }
        return model.history.filter { item in
            item.names.contains { $0.localizedCaseInsensitiveContains(search) }
                || item.manifestHash.hasPrefix(search.lowercased())
        }
    }
}
