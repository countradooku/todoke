// Liquid Glass where the system has it (iOS 26 and later), the closest
// system material before. Standard bars, tab bars, and sheets adopt it on
// their own; these are for todoke's own surfaces and buttons.

import SwiftUI

extension Color {
    /// A red that reads on the app's surfaces in both appearances (the
    /// system red is too light on white for normal text).
    static let warning = Color(UIColor { traits in
        traits.userInterfaceStyle == .dark
            ? UIColor(red: 1.0, green: 0.45, blue: 0.42, alpha: 1)
            : UIColor(red: 0.74, green: 0.10, blue: 0.10, alpha: 1)
    })
}

extension View {
    /// A glass card (rounded), or a thin material before iOS 26.
    @ViewBuilder
    func glassCard(cornerRadius: CGFloat = 20) -> some View {
        if #available(iOS 26.0, *) {
            glassEffect(.regular, in: .rect(cornerRadius: cornerRadius))
        } else {
            background(.thinMaterial, in: .rect(cornerRadius: cornerRadius))
        }
    }

    /// The prominent action button: glass on iOS 26, bordered before.
    @ViewBuilder
    func primaryAction() -> some View {
        if #available(iOS 26.0, *) {
            buttonStyle(.glassProminent)
        } else {
            buttonStyle(.borderedProminent)
        }
    }

    /// A secondary action button.
    @ViewBuilder
    func secondaryAction() -> some View {
        if #available(iOS 26.0, *) {
            buttonStyle(.glass)
        } else {
            buttonStyle(.bordered)
        }
    }
}
