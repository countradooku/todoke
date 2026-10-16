// Visibility as an App Intent: the Control Center control, the widget's
// button, Shortcuts, and the Action button set it. It changes the shared
// setting; the app applies it to the core (at once if it is running, it
// listens for the change; otherwise when it next starts).

import AppIntents
import Foundation

struct SetVisibilityIntent: SetValueIntent {
    static let title: LocalizedStringResource = "Set todoke visibility"
    static let description = IntentDescription("Shows this device to your contacts, or hides it.")

    @Parameter(title: "Visible to contacts")
    var value: Bool

    init() {}

    init(visible: Bool) {
        value = visible
    }

    func perform() async throws -> some IntentResult {
        AppGroup.hidden = !value
        return .result()
    }
}

struct ToggleVisibilityIntent: AppIntent {
    static let title: LocalizedStringResource = "Toggle todoke visibility"
    static let description = IntentDescription("Hides this device from your contacts, or shows it again.")

    func perform() async throws -> some IntentResult & ReturnsValue<Bool> {
        AppGroup.hidden.toggle()
        return .result(value: !AppGroup.hidden)
    }
}
