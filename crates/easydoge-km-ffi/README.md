# easydoge-km-ffi

UniFFI wrapper crate for EasyDoge KM.

This crate exposes the Rust core API to generated Swift and Kotlin bindings. It should stay thin: behavior belongs in `easydoge-km`, and this crate maps records, enums, and errors across the FFI boundary.

See the workspace [README](../../README.md) and [release guide](../../docs/RELEASE.md).
