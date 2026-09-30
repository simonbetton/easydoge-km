# Bindings

These packages are façades over the Rust `easydoge-km` core crate.

- `uniffi/easydoge_km.udl` is a reference sketch, not a binding-generation input. The authoritative contract is the UniFFI proc-macro API in `crates/easydoge-km-ffi/src/lib.rs`.
- `swift/` is the Swift Package surface for iOS 16+ and macOS 13+.
- `kotlin/` is the Android/Kotlin package surface.
- `expo/` is the Expo Modules API package surface.

Swift, Kotlin, and Expo expose the operations listed in the [API guide](../docs/API.md), including message signing, P2PKH transaction signing, signing envelopes, multisig descriptors, and transaction composition. The Expo bridge is handwritten; platform storage is implemented in Swift/Kotlin, not Rust.

Regenerate UniFFI sources with:

```sh
./scripts/generate-bindings.sh
```

Scratch output is written to `bindings/generated/`. The package surfaces under `swift/` and `kotlin/` include the generated source files that are needed by consumers.

`./scripts/verify.sh` runs the generator with `--check`, which fails when a regenerated file is untracked or differs from the git index. After changing the FFI surface or the UniFFI version, regenerate, review the diff, and stage the files listed by `./scripts/generate-bindings.sh --print-committed-paths`. The generator uses the UniFFI version recorded in `Cargo.lock`.

## Integration status

- The Swift package links `easydoge_km_ffi` using the workspace's `target/debug` path. Build the host library before local tests. An iOS app needs a library built for its device/simulator target and appropriate linking; the XCFramework helper does not automatically install a SwiftPM binary target.
- The Kotlin library targets Android API 24+ and compiles against SDK 36. `scripts/build-android-native-libs.sh` writes ARMv7, ARM64, x86, and x86_64 libraries into its `src/main/jniLibs` directory. JVM tests use the host Rust library. It depends on `androidx.biometric:biometric:1.1.0` for `BiometricPromptWalletAuthenticator`, so consuming builds must have AndroidX enabled and host the prompt in a `FragmentActivity`.
- Expo requires a custom native build. Its Android module depends on a Gradle project named `:easydoge-km`, which the consuming build must include, and on the `:expo-modules-core` project that Expo autolinking adds at the version installed in the app. Its iOS module imports `EasyDogeKM`; the current podspec does not declare that Swift module as a dependency, points at the workspace's `target/release` library, and has a source glob relative to the podspec that needs checking in the consuming build. A standalone npm install does not establish these native dependencies. The podspec declares iOS 16.4+.
- The workspace suite checks Swift/Kotlin wrappers and numeric wire codecs, plus Expo TypeScript. It does not compile the Expo native modules, run an Expo app, or test Keychain/Keystore flows on devices.

See the [storage boundaries](../docs/SECURITY_MODEL.md#storage-boundaries) before relying on stored-wallet handles. Kotlin apps use the persistent Android repository; `inMemory()` does not survive process death.
