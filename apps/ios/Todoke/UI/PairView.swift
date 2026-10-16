// Pairing: show a QR code, scan one (VisionKit), or pair with a code. The QR
// is drawn from the core's modules (no offer text crosses to show it);
// scanning passes only text starting with `TODOKE:`. While this screen is
// open its content is hidden from screen recording and mirroring, and from
// the app switcher's snapshot. Leaving it stops pairing.

import SwiftUI
import Todoke
import VisionKit

struct PairView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State var tab: Tab = .show
    /// Opened by a shortcut, not a tap here: the QR (which starts stranger
    /// advertising, §9) waits for the user to ask.
    var waitForTap = false

    enum Tab: Hashable {
        case show, scan, code
    }

    var body: some View {
        NavigationStack {
            VStack(spacing: 16) {
                Picker("Method", selection: $tab) {
                    Text("Show QR").tag(Tab.show)
                    Text("Scan").tag(Tab.scan)
                    Text("Code").tag(Tab.code)
                }
                .pickerStyle(.segmented)
                .accessibilityIdentifier("pair-method")
                switch tab {
                case .show: ShowQr(waitForTap: waitForTap)
                case .scan: ScanQr { dismiss() }
                case .code: Codes { dismiss() }
                }
                Spacer(minLength: 0)
                Button { dismiss() } label: { Text("Done").frame(maxWidth: .infinity) }
                    .secondaryAction()
                    .accessibilityIdentifier("pair-done")
            }
            .padding()
            .navigationTitle("Pair a device")
            .navigationBarTitleDisplayMode(.inline)
        }
        .secret()
        .onDisappear { Task { try? await model.backend.stopPairing() } }
    }
}

private struct ShowQr: View {
    @Environment(AppModel.self) private var model
    let waitForTap: Bool
    @State private var asked = false
    @State private var qr: QrCode?
    @State private var failed: String?

    var body: some View {
        VStack(spacing: 12) {
            Text("Scan this code with the other device. It works once and expires in 5 minutes.")
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: .infinity, alignment: .leading)
            if let qr {
                QrView(qr: qr)
            } else if let failed {
                Text(failed).foregroundStyle(Color.warning)
            } else if waitForTap && !asked {
                Button("Show a QR code") { asked = true }
                    .primaryAction()
                    .accessibilityIdentifier("show-qr")
            } else {
                ProgressView()
            }
        }
        .task(id: asked) {
            guard !waitForTap || asked, qr == nil else { return }
            do { qr = try await model.backend.showQr() } catch { failed = String(describing: error) }
        }
    }
}

/// The QR code, black on white with its 4-module quiet zone (ISO/IEC 18004).
struct QrView: View {
    let qr: QrCode
    private let quiet = 4

    var body: some View {
        Canvas { context, size in
            let cell = min(size.width, size.height) / CGFloat(qr.width + 2 * quiet)
            context.fill(Path(CGRect(origin: .zero, size: size)), with: .color(.white))
            for y in 0..<qr.width {
                for x in 0..<qr.width where qr.dark(x, y) {
                    let rect = CGRect(x: CGFloat(x + quiet) * cell, y: CGFloat(y + quiet) * cell, width: cell, height: cell)
                    context.fill(Path(rect), with: .color(.black))
                }
            }
        }
        .aspectRatio(1, contentMode: .fit)
        .clipShape(.rect(cornerRadius: 12))
        .accessibilityLabel("A secret QR code for pairing")
        .accessibilityIdentifier("pair-qr")
    }
}

private struct ScanQr: View {
    @Environment(AppModel.self) private var model
    let done: () -> Void
    @State private var failed: String?
    @State private var busy = false

    var body: some View {
        VStack(spacing: 12) {
            Text("Point the camera at the QR code on the other device.")
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: .infinity, alignment: .leading)
            if let failed { Text(failed).foregroundStyle(.red) }
            if DataScannerViewController.isSupported && DataScannerViewController.isAvailable {
                Scanner { text in
                    guard !busy else { return }
                    busy = true
                    Task {
                        do {
                            _ = try await model.backend.scanQr(text)
                            done()
                        } catch {
                            failed = String(describing: error)
                            busy = false
                        }
                    }
                }
                .clipShape(.rect(cornerRadius: 12))
                .aspectRatio(1, contentMode: .fit)
            } else {
                Text("This device cannot scan here (no camera, or camera access is off in Settings).")
                    .foregroundStyle(.secondary)
                    .accessibilityIdentifier("scan-unavailable")
            }
        }
    }
}

/// VisionKit's scanner, QR codes only, passing on only todoke offers.
private struct Scanner: UIViewControllerRepresentable {
    let found: (String) -> Void

    func makeUIViewController(context: Context) -> DataScannerViewController {
        let scanner = DataScannerViewController(
            recognizedDataTypes: [.barcode(symbologies: [.qr])], qualityLevel: .accurate,
            recognizesMultipleItems: false, isHighFrameRateTrackingEnabled: false, isHighlightingEnabled: true)
        scanner.delegate = context.coordinator
        try? scanner.startScanning()
        return scanner
    }

    func updateUIViewController(_ controller: DataScannerViewController, context: Context) {}

    static func dismantleUIViewController(_ controller: DataScannerViewController, coordinator: Coordinator) {
        controller.stopScanning()
    }

    func makeCoordinator() -> Coordinator { Coordinator(found: found) }

    final class Coordinator: NSObject, DataScannerViewControllerDelegate {
        let found: (String) -> Void
        init(found: @escaping (String) -> Void) { self.found = found }

        func dataScanner(_ scanner: DataScannerViewController, didAdd items: [RecognizedItem], allItems: [RecognizedItem]) {
            for case .barcode(let code) in items {
                if let text = code.payloadStringValue, text.hasPrefix("TODOKE:") {
                    found(text)
                    return
                }
            }
        }
    }
}

private struct Codes: View {
    @Environment(AppModel.self) private var model
    let done: () -> Void
    @State private var code: PairingCode?
    @State private var strangers: [Stranger] = []
    @State private var entering: Stranger?
    @State private var typed = ""
    @State private var failed: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("One device shows a code; the other picks it nearby and enters the code.")
                .fixedSize(horizontal: false, vertical: true)
            Button("Show a code") {
                Task {
                    do { code = try await model.backend.showCode() } catch { failed = String(describing: error) }
                }
            }
            .secondaryAction()
            .accessibilityIdentifier("show-code")
            if let code {
                Text(code.code.prefix(5) + " " + code.code.suffix(5))
                    .font(.largeTitle.monospacedDigit())
                    .accessibilityLabel("Code \(code.code.map(String.init).joined(separator: " "))")
                    .accessibilityIdentifier("code")
            }
            if let failed { Text(failed).foregroundStyle(.red) }
            Text("Devices pairing nearby").font(.headline)
            ForEach(strangers, id: \.stranger) { stranger in
                Button("Device \(stranger.stranger.prefix(8))") { entering = stranger }
                    .accessibilityIdentifier("stranger-\(stranger.stranger.prefix(8))")
            }
            if let entering {
                SecureField("10-digit code", text: $typed)
                    .keyboardType(.numberPad)
                    .textContentType(.oneTimeCode)
                    .accessibilityIdentifier("code-field")
                Button("Pair") {
                    Task {
                        do {
                            _ = try await model.backend.enterCode(typed.filter(\.isNumber), stranger: entering.stranger)
                            done()
                        } catch {
                            failed = String(describing: error)
                        }
                    }
                }
                .primaryAction()
                .disabled(typed.filter(\.isNumber).count != 10)
                .accessibilityIdentifier("pair-with-code")
            }
        }
        .task {
            while !Task.isCancelled {
                strangers = (try? await model.backend.strangers()) ?? strangers
                try? await Task.sleep(for: .seconds(2))
            }
        }
    }
}

/// Hides secret content from screen recording, AirPlay mirroring, and the
/// app switcher (iOS has no per-window secure flag).
private struct Secret: ViewModifier {
    @Environment(\.scenePhase) private var phase
    @State private var captured = UIScreen.main.isCaptured

    func body(content: Content) -> some View {
        content
            .privacySensitive()
            .overlay {
                if captured || phase != .active {
                    Rectangle().fill(.background)
                        .overlay(Label("Hidden while the screen is shared", systemImage: "eye.slash"))
                }
            }
            .onReceive(NotificationCenter.default.publisher(for: UIScreen.capturedDidChangeNotification)) { _ in
                captured = UIScreen.main.isCaptured
            }
    }
}

extension View {
    func secret() -> some View { modifier(Secret()) }
}
