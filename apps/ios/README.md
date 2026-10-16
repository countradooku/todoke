# iOS client

The todoke app for iOS 26 and later (iPhone): SwiftUI with Liquid Glass,
over the core through the BoltFFI Swift package (`crates/todoke-ffi`). Rust
owns all protocol, cryptographic, and file logic, consent included; the app
presents state and submits the user's intent. The storage key never leaves
Rust: it lives in the Keychain, behind the Secure Enclave and Face ID. See
[ADR 0017](../../docs/adr/0017-ios.md) for the design and its residual
risks, [ADR 0020](../../docs/adr/0020-ios-radios.md) for direct links,
peer-to-peer Wi-Fi, and point to share (and what happens in the
background), [the design](../../docs/DESIGN.md), and
[the protocol](../../spec/PROTOCOL.md).

A device build needs the Hotspot Configuration and Access Wi-Fi Information
capabilities on the App ID (`Config/App.entitlements`).

| Folder | What |
| --- | --- |
| `Todoke` | The app: the core's lifecycle and backends (`Core`), the screens (`UI`), App Intents |
| `Shared` | What the app and its extensions share: the App Group, the share queue, the Live Activity's data, intents |
| `ShareExtension` | Files from any app's share sheet, queued for a contact |
| `Widgets` | The visibility widget, the transfers' Live Activity, the Control Center control |
| `Tests` | Two real cores in the app's sandbox (pairing over Bonjour, a file sent and received) |
| `UITests` | Every flow against a scripted core, with the accessibility audit; screenshots |
| `Config` | Info.plists and entitlements |

## Build and test

The app links the Swift package through `apps/ios/Bindings`, a link the
script makes. `dev` packs the device and simulator slices with development
sessions and loopback (the tests need them); `release` packs the shipped
package (sessions disabled).

```bash
apps/ios/scripts/bindings.sh dev
```

```bash
xcodebuild test -project apps/ios/Todoke.xcodeproj -scheme TodokeApp -destination 'platform=iOS Simulator,name=iPhone 17 Pro'
```

Screenshots of every screen, light and dark, are attachments of
`TodokeUITests/ScreenshotsTests`; export them from the result bundle:

```bash
xcrun xcresulttool export attachments --path <result.xcresult> --output-path apps/ios/screenshots
```
