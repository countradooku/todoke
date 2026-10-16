// The widget extension: a Home Screen widget showing visibility (with a
// button to change it), the transfers' Live Activity on the Lock Screen and
// in the Dynamic Island, and (iOS 18) a Control Center control for
// visibility, which the Action button can run too. Nothing here names a
// file or shows a fingerprint.

import ActivityKit
import AppIntents
import SwiftUI
import WidgetKit

@main
struct TodokeWidgets: WidgetBundle {
    var body: some Widget {
        VisibilityWidget()
        TransferLiveActivity()
        VisibilityControl()
    }
}

// MARK: Visibility widget

struct VisibilityEntry: TimelineEntry {
    let date: Date
    let hidden: Bool
}

struct VisibilityProvider: TimelineProvider {
    func placeholder(in context: Context) -> VisibilityEntry { VisibilityEntry(date: .now, hidden: false) }

    func getSnapshot(in context: Context, completion: @escaping (VisibilityEntry) -> Void) {
        completion(VisibilityEntry(date: .now, hidden: AppGroup.hidden))
    }

    func getTimeline(in context: Context, completion: @escaping (Timeline<VisibilityEntry>) -> Void) {
        completion(Timeline(entries: [VisibilityEntry(date: .now, hidden: AppGroup.hidden)], policy: .never))
    }
}

struct VisibilityWidget: Widget {
    var body: some WidgetConfiguration {
        StaticConfiguration(kind: "visibility", provider: VisibilityProvider()) { entry in
            VStack(alignment: .leading, spacing: 8) {
                Label("todoke", systemImage: "paperplane.fill").font(.headline)
                Text(entry.hidden ? "Hidden" : "Visible to contacts").font(.subheadline)
                Button(intent: ToggleVisibilityIntent()) {
                    Label(entry.hidden ? "Show" : "Hide", systemImage: entry.hidden ? "eye" : "eye.slash")
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .containerBackground(.fill.tertiary, for: .widget)
        }
        .configurationDisplayName("Visibility")
        .description("Whether your contacts can find this device.")
        .supportedFamilies([.systemSmall])
    }
}

// MARK: Live Activity

struct TransferLiveActivity: Widget {
    var body: some WidgetConfiguration {
        ActivityConfiguration(for: TransferAttributes.self) { context in
            LockScreenView(state: context.state)
                .padding()
                .activityBackgroundTint(nil)
        } dynamicIsland: { context in
            DynamicIsland {
                DynamicIslandExpandedRegion(.leading) {
                    Image(systemName: context.state.incoming ? "arrow.down.circle.fill" : "arrow.up.circle.fill")
                        .font(.title2)
                }
                DynamicIslandExpandedRegion(.trailing) {
                    Text(context.state.fraction, format: .percent.precision(.fractionLength(0)))
                        .monospacedDigit()
                }
                DynamicIslandExpandedRegion(.bottom) {
                    VStack(alignment: .leading, spacing: 6) {
                        Text(title(context.state)).font(.subheadline).lineLimit(1)
                        ProgressView(value: context.state.fraction)
                    }
                }
            } compactLeading: {
                Image(systemName: context.state.incoming ? "arrow.down" : "arrow.up")
            } compactTrailing: {
                Text(context.state.fraction, format: .percent.precision(.fractionLength(0)))
                    .monospacedDigit()
            } minimal: {
                ProgressView(value: context.state.fraction).progressViewStyle(.circular)
            }
        }
    }
}

private struct LockScreenView: View {
    let state: TransferAttributes.ContentState

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Label(title(state), systemImage: state.incoming ? "arrow.down.circle.fill" : "arrow.up.circle.fill")
                    .font(.headline)
                    .lineLimit(1)
                Spacer()
                Text(state.fraction, format: .percent.precision(.fractionLength(0))).monospacedDigit()
            }
            ProgressView(value: state.fraction)
            if !state.transfer.isEmpty {
                Button(intent: CancelTransferIntent(transfer: state.transfer)) {
                    Label("Cancel", systemImage: "xmark")
                }
            }
        }
    }
}

private func title(_ state: TransferAttributes.ContentState) -> String {
    if state.count > 1 { return String(localized: "\(state.count) transfers") }
    if state.peer.isEmpty { return String(localized: "Transferring") }
    return state.incoming ? String(localized: "From \(state.peer)") : String(localized: "To \(state.peer)")
}

// MARK: Control Center

struct VisibilityControl: ControlWidget {
    var body: some ControlWidgetConfiguration {
        StaticControlConfiguration(kind: "org.todoke.ios.visibility") {
            ControlWidgetToggle("todoke", isOn: !AppGroup.hidden, action: SetVisibilityIntent()) { visible in
                Label(visible ? "Visible" : "Hidden", systemImage: visible ? "eye" : "eye.slash")
            }
        }
        .displayName("todoke visibility")
        .description("Shows this device to your contacts, or hides it.")
    }
}
