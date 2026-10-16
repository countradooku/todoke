// Background work, within what iOS allows (PROTOCOL §10.3):
//
// - a transfer the user started keeps going after they leave the app: a
//   continued-processing task on iOS 26 and later (the system shows its
//   progress and the user can stop it), a short background task before;
// - a refresh task lets interrupted transfers resume, for a profile whose
//   key needs no Face ID (a gated key cannot open without the user, and
//   iOS shows no prompt in the background); it runs when iOS chooses.
//
// Nothing is received in the background: the core is not listening then.

import BackgroundTasks
import Foundation
import Todoke

enum BackgroundWork {
    static let resume = "org.todoke.ios.resume"
    static let transfer = "org.todoke.ios.transfer"

    /// Registers the handlers; called once, before the app finishes
    /// launching.
    @MainActor
    static func register(core: CoreService) {
        BGTaskScheduler.shared.register(forTaskWithIdentifier: resume, using: nil) { task in
            Task { @MainActor in await runResume(task, core: core) }
        }
        if #available(iOS 26.0, *) {
            BGTaskScheduler.shared.register(forTaskWithIdentifier: transfer, using: nil) { task in
                guard let task = task as? BGContinuedProcessingTask else {
                    task.setTaskCompleted(success: false)
                    return
                }
                Task { @MainActor in await runTransfer(task, core: core) }
            }
        }
    }

    /// Asks for the next refresh (iOS decides when, at least 15 minutes
    /// from now).
    static func scheduleResume() {
        let request = BGAppRefreshTaskRequest(identifier: resume)
        request.earliestBeginDate = Date().addingTimeInterval(15 * 60)
        try? BGTaskScheduler.shared.submit(request)
    }

    /// The user left the app while files move: keep them going.
    @MainActor
    static func continueTransfers() -> Bool {
        guard #available(iOS 26.0, *) else { return false }
        let request = BGContinuedProcessingTaskRequest(
            identifier: transfer, title: String(localized: "Sending and receiving files"),
            subtitle: String(localized: "todoke finishes the transfers in progress."))
        request.strategy = .fail
        return (try? BGTaskScheduler.shared.submit(request)) != nil
    }

    @MainActor
    private static func runResume(_ task: BGTask, core: CoreService) async {
        scheduleResume()
        guard !core.gated else {
            task.setTaskCompleted(success: true)
            return
        }
        var expired = false
        task.expirationHandler = { expired = true }
        await core.start()
        // Gives interrupted transfers time to reconnect and resume.
        for _ in 0..<25 where !expired {
            try? await Task.sleep(for: .seconds(1))
            if let transfers = try? await core.backend?.transfers(),
               !transfers.contains(where: { [.transferring, .accepted, .interrupted].contains($0.state) }) {
                break
            }
        }
        core.stopUnlessForeground()
        task.setTaskCompleted(success: true)
    }

    @available(iOS 26.0, *)
    @MainActor
    private static func runTransfer(_ task: BGContinuedProcessingTask, core: CoreService) async {
        var expired = false
        task.expirationHandler = { expired = true }
        while !expired {
            guard let transfers = try? await core.backend?.transfers() else { break }
            let moving = transfers.filter { [.accepted, .transferring].contains($0.state) }
            if moving.isEmpty { break }
            let done = moving.reduce(0) { $0 + $1.bytesDone }
            let total = moving.reduce(0) { $0 + $1.bytesTotal }
            task.progress.totalUnitCount = Int64(clamping: total)
            task.progress.completedUnitCount = Int64(clamping: done)
            try? await Task.sleep(for: .seconds(1))
        }
        core.stopUnlessForeground()
        task.setTaskCompleted(success: !expired)
    }
}
