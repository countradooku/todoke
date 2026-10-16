// The system around the core: notifications for offers and finished
// transfers, the Live Activity of transfers in progress, the share
// sheet's contact suggestions, and the share extension's queue.

import ActivityKit
import Foundation
import Intents
import Todoke
import UserNotifications

// MARK: Notifications

/// The core's notifier: offers and finished transfers, told even when no
/// screen listens. A notification shows the sender's name and counts,
/// never file names; on a locked device iOS hides its text by default.
final class Notifications: Notifier, @unchecked Sendable {
    func offerReceived(notice: OfferNotice) {
        let content = UNMutableNotificationContent()
        content.title = String(localized: "Files from \(notice.fromName)")
        content.body = String(localized: "\(notice.files) files, \(Format.bytes(notice.totalBytes)). Open todoke to accept or decline.")
        content.sound = .default
        content.threadIdentifier = "offers"
        post(id: notice.transfer, content)
    }

    func offerGone(transfer: String) {
        UNUserNotificationCenter.current().removeDeliveredNotifications(withIdentifiers: [transfer])
    }

    func transferFinished(transfer: String, text: String) {
        let content = UNMutableNotificationContent()
        content.title = "todoke"
        content.body = text
        content.threadIdentifier = "done"
        post(id: "done-" + transfer, content)
    }

    func missed() {
        UNUserNotificationCenter.current().removeAllDeliveredNotifications()
    }

    private func post(id: String, _ content: UNNotificationContent) {
        UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: id, content: content, trigger: nil))
    }

    static func requestPermission() async {
        _ = try? await UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound, .badge])
    }
}

// MARK: Live Activity

/// One Live Activity for everything moving: started when a transfer moves,
/// updated as it does, ended when nothing moves.
@MainActor
final class TransferActivities {
    private var activity: Activity<TransferAttributes>?

    func update(transfers: [Transfer], contacts: [Contact]) {
        guard ActivityAuthorizationInfo().areActivitiesEnabled else { return }
        let moving = transfers.filter { [.accepted, .transferring].contains($0.state) }
        guard !moving.isEmpty else {
            if let activity {
                let final = activity.content.state
                Task { await activity.end(ActivityContent(state: final, staleDate: nil), dismissalPolicy: .immediate) }
                self.activity = nil
            }
            return
        }
        let one = moving.count == 1 ? moving[0] : nil
        let state = TransferAttributes.ContentState(
            count: moving.count,
            done: moving.reduce(0) { $0 + $1.bytesDone },
            total: moving.reduce(0) { $0 + $1.bytesTotal },
            peer: one.flatMap { transfer in contacts.first { $0.device == transfer.peer }?.name } ?? "",
            incoming: one?.way == .incoming,
            transfer: one?.id ?? "")
        let content = ActivityContent(state: state, staleDate: Date().addingTimeInterval(60))
        if let activity {
            Task { await activity.update(content) }
        } else {
            activity = try? Activity.request(attributes: TransferAttributes(), content: content)
        }
    }
}

// MARK: Share-sheet suggestions

/// Donates a send to the system, so the share sheet suggests the contact.
/// The conversation is the contact's keyed ID, never its fingerprint.
enum Donations {
    static func donate(contact: Contact) {
        let id = AppGroup.shortcutID(for: contact.device)
        let recipient = INPerson(
            personHandle: INPersonHandle(value: id, type: .unknown), nameComponents: nil,
            displayName: contact.name, image: nil, contactIdentifier: nil, customIdentifier: id)
        let intent = INSendMessageIntent(
            recipients: [recipient], outgoingMessageType: .outgoingMessageText, content: nil,
            speakableGroupName: INSpeakableString(spokenPhrase: contact.name), conversationIdentifier: id,
            serviceName: nil, sender: nil, attachments: nil)
        INInteraction(intent: intent, response: nil).donate(completion: nil)
    }

    /// Forgets the donations of contacts no longer there.
    static func forget(except contacts: [Contact]) {
        let kept = Set(contacts.map { AppGroup.shortcutID(for: $0.device) })
        let stale = AppGroup.contacts.map(\.id).filter { !kept.contains($0) }
        if !stale.isEmpty {
            INInteraction.delete(with: stale)
        }
    }
}

// MARK: The share queue

/// Sends what the share extension (or a shortcut) queued, once the core
/// runs: each request is sent once (marked with its transfer), and its files
/// are removed once that transfer ends. One pass at a time. A request that
/// fails is tried again later, backing off, and dropped (and the user told)
/// after a few tries; a folder the extension never finished goes after a
/// day.
@MainActor
final class Outbox {
    private struct Sent: Codable {
        var transfer: String
    }

    private static let sentFile = "sent.json"
    private static let tries = 5
    private static let unfinishedFor: TimeInterval = 24 * 60 * 60

    private var processing = false
    /// Failed tries per request folder: how many, and not before when.
    private var failures: [String: (count: Int, next: Date)] = [:]

    /// Sends what waits; returns the names of the contacts whose files
    /// were dropped after failing.
    func process(backend: Backend, contacts: [Contact], active: Set<String>) async -> [String] {
        guard !processing else { return [] }
        processing = true
        defer { processing = false }
        let files = FileManager.default
        guard let folders = try? files.contentsOfDirectory(
            at: AppGroup.outbox, includingPropertiesForKeys: [.creationDateKey])
        else {
            return []
        }
        var dropped: [String] = []
        for folder in folders {
            let sent = folder.appendingPathComponent(Self.sentFile)
            if let data = try? Data(contentsOf: sent), let record = try? JSONDecoder().decode(Sent.self, from: data) {
                // Sent before: the files go once that transfer has ended.
                if !active.contains(record.transfer) {
                    try? files.removeItem(at: folder)
                }
                continue
            }
            guard let data = try? Data(contentsOf: folder.appendingPathComponent(AppGroup.requestFile)),
                  let request = try? JSONDecoder().decode(AppGroup.QueuedShare.self, from: data)
            else {
                // The extension stopped before writing the request.
                let created = (try? folder.resourceValues(forKeys: [.creationDateKey]))?.creationDate
                if let created, Date().timeIntervalSince(created) > Self.unfinishedFor {
                    try? files.removeItem(at: folder)
                }
                continue
            }
            guard let contact = contacts.first(where: { AppGroup.shortcutID(for: $0.device) == request.contact }) else {
                // The contact is gone: nothing will send these.
                try? files.removeItem(at: folder)
                continue
            }
            let key = folder.lastPathComponent
            if let failed = failures[key], failed.next > Date() { continue }
            let paths = request.names.map { folder.appendingPathComponent($0).path }
            do {
                let transfer = try await backend.send(to: contact.device, paths: paths)
                failures[key] = nil
                if let record = try? JSONEncoder().encode(Sent(transfer: transfer)) {
                    try? record.write(to: sent, options: [.atomic, .completeFileProtectionUnlessOpen])
                }
                Donations.donate(contact: contact)
            } catch {
                let count = (failures[key]?.count ?? 0) + 1
                if count >= Self.tries {
                    failures[key] = nil
                    try? files.removeItem(at: folder)
                    dropped.append(contact.name)
                } else {
                    failures[key] = (count, Date().addingTimeInterval(pow(2, Double(count)) * 5))
                }
            }
        }
        return dropped
    }
}
