# iOS client

Reserved for a thin SwiftUI client backed by the Rust core through BoltFFI. No Xcode project, generated binding, or runnable app exists yet.

Rust owns all protocol, cryptographic, and file logic, including consent enforcement. The UI presents state and submits user intent. No secrets may cross FFI. Verify iOS API availability, entitlements, BoltFFI target support, and packaging before introducing the client. A Rust cross-target check does not validate an iOS app, and macOS API support does not imply iOS availability.

Read [the design](../../docs/DESIGN.md) and [protocol baseline](../../spec/PROTOCOL.md) before implementation.
