// The app: the core starts when the app comes to the foreground and stops
// when it leaves it with nothing moving (PROTOCOL §10.3: no listeners in
// the background). Shared changes (visibility from Control Center or the
// widget, a share queued by the extension) are picked up as they happen.

import SwiftUI

@main
struct TodokeApp: App {
    @State private var core = CoreService()
    @Environment(\.scenePhase) private var phase

    var body: some Scene {
        WindowGroup {
            RootView()
                .environment(core)
                .task { await Notifications.requestPermission() }
        }
        .onChange(of: phase) { _, phase in
            switch phase {
            case .active:
                Task { await core.start() }
            case .background:
                core.enteredBackground(moving: Moving.now)
            default:
                break
            }
        }
    }
}

/// Whether something moves now, as the screens last read it.
@MainActor
enum Moving {
    static var now = false
}
