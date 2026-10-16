// The app's screen: why the core is not running (unlock, starting, disabled,
// failed), or the four tabs with the pairing and receive sheets above them.

import SwiftUI
import Todoke

struct RootView: View {
    @Environment(CoreService.self) private var core

    var body: some View {
        switch core.state {
        case .ready:
            if let backend = core.backend {
                Tabs(backend: backend)
            }
        case .locked(let gated):
            Message(text: gated ? "todoke is locked." : "Opening todoke…", systemImage: "lock") {
                if gated {
                    Button("Unlock") { Task { await core.start() } }
                        .primaryAction()
                        .accessibilityIdentifier("unlock")
                }
            }
        case .starting:
            Message(text: "Opening todoke…", systemImage: "hourglass") { ProgressView() }
        case .disabled:
            Message(text: "This build keeps transfers disabled (development builds only).",
                    systemImage: "nosign") { EmptyView() }
        case .failed(let message):
            Message(text: message, systemImage: "exclamationmark.triangle") {
                Button("Try again") { Task { await core.start() } }.primaryAction()
            }
        }
    }
}

private struct Message<Actions: View>: View {
    let text: LocalizedStringKey
    let systemImage: String
    @ViewBuilder let actions: () -> Actions

    init(text: String, systemImage: String, @ViewBuilder actions: @escaping () -> Actions) {
        self.text = LocalizedStringKey(text)
        self.systemImage = systemImage
        self.actions = actions
    }

    var body: some View {
        ContentUnavailableView {
            Label(text, systemImage: systemImage)
        } actions: {
            actions()
        }
    }
}

/// An offer the receive sheet shows (sheets need identity).
private struct Shown: Identifiable {
    let offer: Offer
    var id: String { offer.transfer }
}

private struct Tabs: View {
    @State private var model: AppModel
    @State private var pairing = false
    @State private var pairingTab: PairView.Tab = .show
    @State private var hiddenOffers: Set<String> = []
    @Environment(\.scenePhase) private var phase
    @Environment(CoreService.self) private var core

    init(backend: Backend) {
        _model = State(initialValue: AppModel(backend: backend))
    }

    var body: some View {
        TabView {
            HomeView(pairing: $pairing)
                .tabItem { Label("Home", systemImage: "house") }
            TransfersView()
                .tabItem { Label("Transfers", systemImage: "arrow.up.arrow.down") }
            HistoryView()
                .tabItem { Label("History", systemImage: "clock") }
            SettingsView(pairingCode: Binding(get: { pairing && pairingTab == .code }, set: { show in
                pairingTab = .code
                pairing = show
            }))
            .tabItem { Label("Settings", systemImage: "gear") }
        }
        .environment(model)
        .sheet(isPresented: $pairing, onDismiss: { pairingTab = .show }) {
            PairView(tab: pairingTab).environment(model)
        }
        .sheet(item: Binding(get: { shown }, set: { value in
            // Swiped away: hidden until it changes; the offer stays (§13).
            if value == nil, let current = shown { hiddenOffers.insert(current.id) }
        })) { shown in
            ReceiveSheet(offer: shown.offer) { files in
                Task { await model.accept(shown.offer, files: files) }
            } decline: {
                Task { await model.decline(shown.offer) }
            }
        }
        .alert("todoke", isPresented: Binding(get: { model.notice != nil }, set: { if !$0 { model.notice = nil } })) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(model.notice ?? "")
        }
        .onAppear {
            model.onIdle = { [core] in core.transfersIdle() }
            model.run()
        }
        #if DEBUG
        .overlay(alignment: .top) { FakeRequestLabel() }
        #endif
        .onChange(of: phase) { _, phase in
            if phase == .active {
                model.run()
                // Shortcuts' "Pair a device" opens pairing.
                if UserDefaults.standard.bool(forKey: "open-pairing") {
                    UserDefaults.standard.removeObject(forKey: "open-pairing")
                    pairing = true
                }
            } else if phase == .background {
                model.pause()
            }
        }
    }

    private var shown: Shown? {
        model.offers.first { !hiddenOffers.contains($0.transfer) }.map(Shown.init)
    }
}

#if DEBUG
/// The scripted core's requests, in order and separated by "|", for the UI
/// tests to read (debug builds running a test scenario only).
private struct FakeRequestLabel: View {
    @State private var requests = ""

    var body: some View {
        Text(requests)
            .font(.caption2)
            .accessibilityIdentifier("fake-request")
            .onReceive(NotificationCenter.default.publisher(for: .fakeRequest).receive(on: RunLoop.main)) { note in
                if let request = note.object as? String { requests += "|" + request }
            }
            .allowsHitTesting(false)
    }
}
#endif
