# Bindings

These packages are façades over the Rust `easydoge-km` core crate.

- `uniffi/easydoge_km.udl` documents the shared native binding contract. The active FFI crate uses UniFFI proc macros.
- `swift/` is the Swift Package surface for iOS.
- `kotlin/` is the Android/Kotlin package surface.
- `expo/` is the Expo Modules API package surface.

Regenerate UniFFI sources with:

```sh
./scripts/generate-bindings.sh
```

Scratch output is written to `bindings/generated/`. The package surfaces under `swift/` and `kotlin/` include the generated source files that are needed by consumers.
