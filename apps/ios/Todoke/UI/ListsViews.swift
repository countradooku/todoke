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

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Label(transfer.way == .incoming ? "From \(peer)" : "To \(peer)",
                      systemImage: transfer.way == .incoming ? "arrow.down.circle" : "arrow.up.circle")
                Spacer()
                if cancellable {
                    Button("Cancel", role: .destructive, action: cancel)
                        .buttonStyle(.borderless)
                        .accessibilityIdentifier("cancel-\(transfer.id.prefix(4))")
                }
            }
            ProgressView(value: fraction)
                .accessibilityLabel("Progress")
                .accessibilityValue("\(Int(fraction * 100)) percent")
            Text("\(Format.bytes(transfer.bytesDone)) of \(Format.bytes(transfer.bytesTotal)) · \(Format.state(transfer.state))")
                .font(.caption)
                .foregroundStyle(.secondary)
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
                    List(filtered, id: \.transfer) { item in
                        VStack(alignment: .leading, spacing: 4) {
                            Text(item.names.joined(separator: ", ")).font(.headline).lineLimit(2)
                            Text("\(Format.state(item.state)) · \(Format.bytes(item.bytes))")
                                .font(.caption).foregroundStyle(.secondary)
                            Text(item.manifestHash.prefix(16)).font(.caption2.monospaced()).foregroundStyle(.secondary)
                                .accessibilityLabel("Manifest hash \(item.manifestHash.prefix(16))")
                        }
                        .accessibilityElement(children: .combine)
                    }
                    .searchable(text: $search)
                }
            }
            .navigationTitle("History")
            .toolbar {
                if !model.history.isEmpty {
                    Button("Clear", role: .destructive) { confirming = true }
                        .accessibilityIdentifier("clear-history")
                }
            }
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
