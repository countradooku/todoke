// The core's lifecycle. It starts once (a start in progress is shared),
// off the main thread: it blocks while the profile opens, and with a gated
// key the system asks for Face ID, Touch ID, or the passcode then. When the
// app leaves the foreground it stops, unless a continued-processing task
// the user started runs: then it stays in its background mode, no
// listener, no advertising, no relay presence (PROTOCOL §10.3), until that
// task ends. A stop while a start is under way wins: the core that start
// opens is released at once.

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
    /// Bumped by each stop: a start that a stop overtook drops its core.
    private var generation = 0
    /// The core runs in its background mode.
    private var inBackground = false
    private let notifier = Notifications()
    /// Direct Wi-Fi links (§10.2), set up only while the app is in use.
    private let links = AppleLinks()

    /// The key needs the user: decided when the profile is created (when
    /// the device has a passcode then), and fixed with it (the key's access
    /// control is set when it is stored). Decided again whenever there is
    /// no profile, as after a restore from a backup (the state is never in
    /// one, while the app's defaults are).
    let gated: Bool

    init() {
        let defaults = UserDefaults.standard
        let profile = FileManager.default.fileExists(atPath: Paths.home.appendingPathComponent("state").path)
        if defaults.object(forKey: "gate") == nil || !profile {
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
        let generation = generation
        state = .starting
        let settings = Settings(
            home: Paths.home.path, downloads: Paths.received.path, lan: true, allowLoopback: false,
            hidden: AppGroup.hidden, historyDays: 30, keyStorage: .platform)
        let gated = gated
        let notifier = notifier
        let links = links
        let result: Result<Core, Error> = await Task.detached(priority: .userInitiated) {
            Result {
                try Paths.prepare()
                let core = gated ? try Core(withPresence: settings) : try Core(settings: settings)
                core.setNotifier(notifier: notifier)
                try core.setLinks(links: links)
                return core
            }
        }.value
        // Stopped meanwhile (the app left the screen): the core goes now,
        // closing its listener.
        guard generation == self.generation else {
            state = .locked(gated: gated)
            return
        }
        switch result {
        case .success(let core):
            backend = CoreBackend(core: core)
            state = .ready
            links.setAllowed(true)
        case .failure(TodokeError.disabled(let message)):
            state = .disabled(message)
        case .failure(TodokeError.locked):
            // Face ID refused or cancelled: ask again when the user wants.
            state = .locked(gated: gated)
        case .failure(let error):
            state = .failed(String(describing: error))
        }
    }

    /// Releases the core: it stops, closing its listeners. A start under
    /// way drops the core it opens.
    func stop() {
        #if DEBUG
        if UserDefaults.standard.string(forKey: "ui-test-scenario") != nil { return }
        #endif
        generation += 1
        links.setAllowed(false)
        backend = nil
        inBackground = false
        switch state {
        case .ready, .starting: state = .locked(gated: gated)
        default: break
        }
    }

    /// The app left the foreground: the core stops, unless a
    /// continued-processing task the user started runs; then it goes on in
    /// its background mode until the task ends.
    func enteredBackground() {
        guard BackgroundWork.running, let backend else {
            stop()
            return
        }
        inBackground = true
        // A joined network goes 15 seconds after the app leaves the screen:
        // no new link in the background.
        links.setAllowed(false)
        Task {
            do {
                try await backend.setBackground(true)
            } catch {
                stop()
            }
        }
    }

    /// The app is on screen: the core starts, or leaves its background
    /// mode (the listener reopens).
    func enteredForeground() async {
        if inBackground, let backend {
            inBackground = false
            do {
                try await backend.setBackground(false)
                links.setAllowed(true)
                return
            } catch {
                stop()
            }
        }
        await start()
    }

    /// The continued-processing task ended: the core stops unless the app
    /// is on screen.
    func backgroundWorkEnded() {
        if UIApplication.shared.applicationState != .active { stop() }
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
