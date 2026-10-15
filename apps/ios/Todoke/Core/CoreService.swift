// The core's lifecycle. It starts once (a start in progress is shared),
// off the main thread: it blocks while the profile opens, and with a gated
// key the system asks for Face ID, Touch ID, or the passcode then. It
// stops when the app leaves the foreground with nothing moving (an iOS app
// closes its listeners in the background, PROTOCOL §10.3), and otherwise
// once what moves is done, within the time iOS gives.

import BackgroundTasks
import Foundation
import LocalAuthentication
import Observation
import Todoke
import UIKit

enum CoreState: Equatable {
    /// Not started, or waiting for the user to unlock (`gated`).
    case locked(gated: Bool)
    case starting
    case ready
    /// This build keeps sessions disabled (PROTOCOL §16).
    case disabled(String)
    case failed(String)
}

@MainActor
@Observable
final class CoreService {
    private(set) var state: CoreState
    private(set) var backend: Backend?
    private var starting: Task<Void, Never>?
    private var background: UIBackgroundTaskIdentifier = .invalid
    private let notifier = Notifications()

    /// The key needs the user (decided once, at the first launch: when the
    /// device has a passcode). Kept in the app's own defaults.
    let gated: Bool

    init() {
        let defaults = UserDefaults.standard
        if defaults.object(forKey: "gate") == nil {
            defaults.set(LAContext().canEvaluatePolicy(.deviceOwnerAuthentication, error: nil), forKey: "gate")
        }
        gated = defaults.bool(forKey: "gate")
        state = .locked(gated: gated)
        #if DEBUG
        if let scenario = UserDefaults.standard.string(forKey: "ui-test-scenario") {
            backend = FakeBackend.scenario(scenario)
            state = .ready
        }
        #endif
    }

    /// Starts the core unless it runs; returns once it is ready or did not
    /// start. Callers at the same time share one start.
    func start() async {
        if case .ready = state { return }
        if let starting {
            await starting.value
            return
        }
        let task = Task { await open() }
        starting = task
        await task.value
        starting = nil
    }

    private func open() async {
        state = .starting
        let settings = Settings(
            home: Paths.home.path, downloads: Paths.received.path, lan: true, allowLoopback: false,
            hidden: AppGroup.hidden, historyDays: 30, keyStorage: .platform)
        let gated = gated
        let notifier = notifier
        let result: Result<Core, Error> = await Task.detached(priority: .userInitiated) {
            Result {
                try Paths.prepare()
                let core = gated ? try Core(withPresence: settings) : try Core(settings: settings)
                core.setNotifier(notifier: notifier)
                return core
            }
        }.value
        switch result {
        case .success(let core):
            backend = CoreBackend(core: core)
            state = .ready
        case .failure(TodokeError.disabled(let message)):
            state = .disabled(message)
        case .failure(TodokeError.locked):
            // Face ID refused or cancelled: ask again when the user wants.
            state = .locked(gated: gated)
        case .failure(let error):
            state = .failed(String(describing: error))
        }
    }

    /// Releases the core: it stops, closing its listeners.
    func stop() {
        #if DEBUG
        if UserDefaults.standard.string(forKey: "ui-test-scenario") != nil { return }
        #endif
        backend = nil
        if case .ready = state { state = .locked(gated: gated) }
        endBackgroundTask()
    }

    /// The app left the foreground: stop now if nothing moves, otherwise
    /// keep running while iOS allows (a background task; on iOS 26 a
    /// continued-processing task the system shows) and stop when done.
    func enteredBackground(moving: Bool) {
        guard moving else {
            stop()
            return
        }
        background = UIApplication.shared.beginBackgroundTask(withName: "todoke transfer") { [weak self] in
            Task { @MainActor in self?.stop() }
        }
    }

    /// Nothing moves any more while in the background.
    func transfersIdle() {
        if background != .invalid { stop() }
    }

    private func endBackgroundTask() {
        if background != .invalid {
            UIApplication.shared.endBackgroundTask(background)
            background = .invalid
        }
    }
}

/// Where the core keeps things. The state (identity, contacts, history,
/// the quarantine) in Application Support, excluded from backups; received
/// files in Documents/Received, which the Files app shows.
enum Paths {
    static var home: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("todoke", isDirectory: true)
    }

    static var received: URL {
        FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("Received", isDirectory: true)
    }

    /// Creates the folders; the state never goes into a backup (a restored
    /// backup must never bring back old keys or pairings, PROTOCOL §16 O3).
    static func prepare() throws {
        let files = FileManager.default
        for folder in [home, received] {
            try files.createDirectory(at: folder, withIntermediateDirectories: true)
        }
        var state = home
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try state.setResourceValues(values)
    }
}
