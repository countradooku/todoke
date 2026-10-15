// swift-tools-version:5.9
// Smoke tests of the Swift bindings, against the package BoltFFI generates
// into ../target-tests/apple (boltffi --overlay boltffi.test.toml pack apple)
// or, with TODOKE_SWIFT_PACKAGE set, another one (the release package, whose
// cores refuse to start: TODOKE_RELEASE=1 runs only that check).
import Foundation
import PackageDescription

let bindings = ProcessInfo.processInfo.environment["TODOKE_SWIFT_PACKAGE"] ?? "../target-tests/apple"

let package = Package(
    name: "TodokeBindingTests",
    platforms: [.macOS(.v13)],
    dependencies: [
        .package(name: "Todoke", path: bindings),
    ],
    targets: [
        .testTarget(
            name: "TodokeTests",
            dependencies: [.product(name: "Todoke", package: "Todoke")]
        ),
    ]
)
