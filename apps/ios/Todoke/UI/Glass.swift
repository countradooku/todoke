// Liquid Glass for todoke's own surfaces and buttons; standard bars, tab
// bars, and sheets adopt it on their own.

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
    /// A glass card (rounded).
    func glassCard(cornerRadius: CGFloat = 20) -> some View {
        glassEffect(.regular, in: .rect(cornerRadius: cornerRadius))
    }

    /// The prominent action button.
    func primaryAction() -> some View {
        buttonStyle(.glassProminent)
    }

    /// A secondary action button.
    func secondaryAction() -> some View {
        buttonStyle(.glass)
    }
}
