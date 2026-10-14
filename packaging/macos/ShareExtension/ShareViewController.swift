// "todoke" in the Share menu: hands the shared files and folders to the
// containing todoke.app, which sends them as it does files opened with it
// (Finder's Open With). Built by build-app.sh with swiftc; it loads only
// when signed.

import AppKit
import UniformTypeIdentifiers

@objc(TodokeShareViewController)
final class ShareViewController: NSViewController {
    /// The URLs read so far (providers answer on background queues).
    private let lock = NSLock()
    private var urls: [URL] = []

    override func loadView() {
        // No interface: the request completes as soon as the app has the files.
        view = NSView(frame: .zero)
    }

    override func viewDidLoad() {
        super.viewDidLoad()
        guard let context = extensionContext else { return }
        let fileURL = UTType.fileURL.identifier
        let providers = context.inputItems
            .compactMap { $0 as? NSExtensionItem }
            .flatMap { $0.attachments ?? [] }
            .filter { $0.hasItemConformingToTypeIdentifier(fileURL) }
        guard !providers.isEmpty else {
            context.cancelRequest(withError: CocoaError(.fileNoSuchFile))
            return
        }
        let group = DispatchGroup()
        for provider in providers {
            group.enter()
            provider.loadItem(forTypeIdentifier: fileURL, options: nil) { [self] item, _ in
                defer { group.leave() }
                if let url = Self.fileURL(item) {
                    lock.lock()
                    urls.append(url)
                    lock.unlock()
                }
            }
        }
        group.notify(queue: .main) { [self] in
            lock.lock()
            let shared = urls
            lock.unlock()
            open(shared, context: context)
        }
    }

    /// A local file's URL, however the provider encoded it.
    private static func fileURL(_ item: NSSecureCoding?) -> URL? {
        let url: URL?
        switch item {
        case let value as URL:
            url = value
        case let data as Data:
            url = URL(dataRepresentation: data, relativeTo: nil)
        case let text as String:
            url = URL(string: text)
        default:
            url = nil
        }
        guard let url, url.isFileURL else { return nil }
        return url
    }

    private func open(_ shared: [URL], context: NSExtensionContext) {
        guard !shared.isEmpty, let app = Self.containingApp() else {
            context.cancelRequest(withError: CocoaError(.fileNoSuchFile))
            return
        }
        let configuration = NSWorkspace.OpenConfiguration()
        configuration.activates = true
        NSWorkspace.shared.open(shared, withApplicationAt: app, configuration: configuration) { _, error in
            DispatchQueue.main.async {
                if let error {
                    context.cancelRequest(withError: error)
                } else {
                    context.completeRequest(returningItems: nil, completionHandler: nil)
                }
            }
        }
    }

    /// todoke.app: this extension lives in todoke.app/Contents/PlugIns.
    private static func containingApp() -> URL? {
        var url = Bundle.main.bundleURL.standardizedFileURL
        while url.pathComponents.count > 1 {
            url.deleteLastPathComponent()
            if url.pathExtension == "app" {
                return url
            }
        }
        return nil
    }
}
