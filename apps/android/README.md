# Android client

Reserved for a thin Jetpack Compose client backed by the Rust core through BoltFFI. No Android project, generated binding, or runnable app exists yet.

Rust owns all protocol, cryptographic, and file logic, including consent enforcement. The UI presents state and submits user intent. No secrets may cross FFI. Verify Android API requirements, BoltFFI target support, and packaging before introducing the client. A Rust cross-target check does not validate an Android app.

Read [the design](../../docs/DESIGN.md) and [protocol baseline](../../spec/PROTOCOL.md) before implementation.
