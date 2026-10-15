// Liquid Glass where the system has it (iOS 26 and later), the closest
// system material before. Standard bars, tab bars, and sheets adopt it on
// their own; these are for todoke's own surfaces and buttons.

import SwiftUI

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
