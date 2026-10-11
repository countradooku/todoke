# Web bindings

Reserved for web bindings to the Rust core through BoltFFI. No web app, generated binding, or JavaScript package exists yet.

BoltFFI's web-target support and the build, packaging, and browser integration requirements must be verified against official documentation before implementation. Rust retains all protocol, cryptographic, and file logic. No secrets may cross FFI. The scaffold's `wasm32-unknown-unknown` compile check establishes only that its empty Rust libraries compile for that target.

Read [the design](../docs/DESIGN.md) and [protocol baseline](../spec/PROTOCOL.md) before implementation.
