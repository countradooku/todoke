// swift-tools-version:5.9
// Smoke tests of the Swift bindings, against the package BoltFFI generates
// into ../target-tests/apple (boltffi --overlay boltffi.test.toml pack apple).
import PackageDescription

let package = Package(
    name: "TodokeBindingTests",
    platforms: [.macOS(.v13)],
    dependencies: [
        .package(name: "Todoke", path: "../target-tests/apple"),
    ],
    targets: [
        .testTarget(
            name: "TodokeTests",
            dependencies: [.product(name: "Todoke", package: "Todoke")]
        ),
    ]
)
