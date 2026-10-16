// Background work, within what PROTOCOL §10.3 and iOS allow: a transfer
// runs in the foreground, or in a continued-processing task the user
// started (iOS 26 and later). The task is asked for when the user sends or
// accepts, in the foreground, as iOS requires; the system shows its
// progress and the user can stop it. While the app is in the background
// the core keeps no listener, advertises nothing, and has no relay
// presence (`setBackground`): only the transfers already going move.
//
// Nothing else runs in the background: no refresh task resumes transfers
// on its own (it would have to start the core, which listens), and before
// iOS 26 the core stops when the app leaves the screen; interrupted
// transfers resume when the user opens the app again (§7.5).

import BackgroundTasks
import Foundation
import Todoke
import UIKit

@MainActor
enum BackgroundWork {
    static let transfer = "org.todoke.ios.transfer"

    /// Whether a continued-processing task runs now.
    private(set) static var running = false

    /// Registers the handler; called once, before the app finishes
    /// launching.
    static func register(core: CoreService) {
        guard #available(iOS 26.0, *) else { return }
        BGTaskScheduler.shared.register(forTaskWithIdentifier: transfer, using: nil) { task in
            guard let task = task as? BGContinuedProcessingTask else {
                task.setTaskCompleted(success: false)
                return
            }
            Task { @MainActor in await run(task, core: core) }
        }
    }

    /// The user started a transfer (in the foreground): ask iOS to let it
    /// finish if they leave the app. Once at a time.
    static func userStartedTransfer() {
        guard #available(iOS 26.0, *), !running else { return }
        #if DEBUG
        // The scripted core of the UI tests has nothing to finish.
        if UserDefaults.standard.string(forKey: "ui-test-scenario") != nil { return }
        #endif
        let request = BGContinuedProcessingTaskRequest(
            identifier: transfer, title: String(localized: "Sending and receiving files"),
            subtitle: String(localized: "todoke finishes the transfers in progress."))
        // Starts now or not at all: never later, when the user is gone.
        request.strategy = .fail
        running = (try? BGTaskScheduler.shared.submit(request)) != nil
    }

    @available(iOS 26.0, *)
    private static func run(_ task: BGContinuedProcessingTask, core: CoreService) async {
        running = true
        var expired = false
        task.expirationHandler = { expired = true }
        // The transfer may take a moment to show as moving.
        var idle = 0
        while !expired, idle < 5 {
            guard let transfers = try? await core.backend?.transfers() else { break }
            let moving = transfers.filter { [.accepted, .transferring].contains($0.state) }
            if moving.isEmpty {
                idle += 1
            } else {
                idle = 0
                let done = moving.reduce(0) { $0 + $1.bytesDone }
                let total = moving.reduce(0) { $0 + $1.bytesTotal }
                task.progress.totalUnitCount = Int64(clamping: total)
                task.progress.completedUnitCount = Int64(clamping: done)
            }
            try? await Task.sleep(for: .seconds(1))
        }
        running = false
        core.backgroundWorkEnded()
        task.setTaskCompleted(success: !expired)
    }
}
