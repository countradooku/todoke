// The screens' state: what the core reports, read every two seconds while a
// screen shows and again on each of its events, and the user's actions.

import Foundation
import Observation
import Todoke

@MainActor
@Observable
final class AppModel {
    var status: Status?
    var contacts: [Contact] = []
    var transfers: [Transfer] = []
    var offers: [Offer] = []
    var history: [HistoryItem] = []
    /// A short message for the user (an action that failed).
    var notice: String?

    @ObservationIgnored let backend: Backend
    @ObservationIgnored private let activities = TransferActivities()
    @ObservationIgnored private let outbox = Outbox()
    @ObservationIgnored private var tasks: [Task<Void, Never>] = []
    /// A refresh runs (it suspends at each call); another asked meanwhile
    /// runs once it ends, never alongside it.
    @ObservationIgnored private var refreshing = false
    @ObservationIgnored private var again = false

    init(backend: Backend) {
        self.backend = backend
    }

    /// Reads everything now, then on every event and every two seconds.
    func run() {
        guard tasks.isEmpty else { return }
        tasks.append(Task { [weak self] in
            while !Task.isCancelled {
                await self?.refresh()
                try? await Task.sleep(for: .seconds(2))
            }
        })
        let events = backend.events()
        tasks.append(Task { [weak self] in
            for await _ in events {
                await self?.refresh()
            }
        })
    }

    func pause() {
        tasks.forEach { $0.cancel() }
        tasks = []
    }

    var moving: Bool {
        transfers.contains { [.accepted, .transferring].contains($0.state) }
    }

    func refresh() async {
        guard !refreshing else {
            again = true
            return
        }
        refreshing = true
        defer { refreshing = false }
        repeat {
            again = false
            await refreshOnce()
        } while again
    }

    private func refreshOnce() async {
        guard let status = try? await backend.status() else { return }
        self.status = status
        contacts = (try? await backend.contacts()) ?? contacts
        transfers = (try? await backend.transfers()) ?? transfers
        offers = (try? await backend.offers()) ?? offers
        history = (try? await backend.history()) ?? history
        AppGroup.contacts = contacts.map {
            AppGroup.SharedContact(id: AppGroup.shortcutID(for: $0.device), name: $0.name, available: $0.available)
        }
        activities.update(transfers: transfers, contacts: contacts)
        if status.hidden != AppGroup.hidden {
            try? await backend.setHidden(AppGroup.hidden)
        }
        for transfer in CancelRequests.take() {
            try? await backend.cancel(transfer)
        }
        let active = Set(transfers.filter { ![.received, .delivered, .unconfirmed, .rejected, .cancelled, .failed].contains($0.state) }.map(\.id))
        let dropped = await outbox.process(backend: backend, contacts: contacts, active: active)
        if !dropped.isEmpty {
            notice = String(localized: "Files shared for \(dropped.joined(separator: ", ")) could not be sent and were removed.")
        }
    }

    // MARK: Actions

    private func perform(_ action: () async throws -> Void) async {
        do {
            try await action()
        } catch {
            notice = String(describing: error)
        }
        await refresh()
    }

    func send(to contact: Contact, documents: [Picked]) async {
        await perform {
            _ = try await backend.send(to: contact.device, documents: documents)
            BackgroundWork.userStartedTransfer()
            Donations.donate(contact: contact)
        }
    }

    func accept(_ offer: Offer, files: [UInt32]) async {
        await perform {
            try await backend.accept(offer.transfer, files: files)
            BackgroundWork.userStartedTransfer()
        }
    }

    func decline(_ offer: Offer) async {
        await perform { try await backend.decline(offer.transfer) }
    }

    func cancel(_ transfer: Transfer) async {
        await perform { try await backend.cancel(transfer.id) }
    }

    func clearHistory() async {
        await perform { try await backend.clearHistory() }
    }

    func setHidden(_ hidden: Bool) async {
        AppGroup.hidden = hidden
        await perform { try await backend.setHidden(hidden) }
    }
}
