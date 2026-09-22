# Contributing

Thank you for working on EasyDoge KM. This SDK handles wallet key material, so contributions need to keep API parity, test evidence, and security boundaries explicit.

## Development Setup

Install:

- Rust 1.91 or newer (workspace MSRV) with `rustfmt` and `clippy`
- Swift 6 or newer for the Swift package checks
- JDK 17 for Android/Kotlin checks
- Node.js 20 or newer and pnpm for Expo TypeScript and bitcoinjs cross-checks
- Bash and ripgrep for the verification scripts
- Android SDK platform 36, with `ANDROID_HOME` or `bindings/kotlin/local.properties` pointing to the SDK

Run the full suite on macOS with an Apple development toolchain: the Swift storage implementation imports Security and LocalAuthentication. The Android NDK and `cargo-ndk` are needed only for native Android artifact builds.

Then run:

```sh
./scripts/verify.sh
```

This regenerates the committed UniFFI sources. Review any resulting diff. Expo verification is TypeScript-only; the native Expo modules and device storage/authentication flows require separate integration tests. Kotlin tests use the host Rust library, not an Android device. To syntax-check every shell script, run `bash -c 'for script in scripts/*.sh; do bash -n "$script" || exit; done'`; the existing `bash -n scripts/*.sh` invocation checks only the first script.

## Development Rules

- Use TDD for behavior changes. Add or update a failing public-interface test first, then implement the smallest change that makes it pass.
- Keep Rust as the canonical implementation. Swift, Kotlin, Expo, CLI, and TUI behavior must call or mirror the same Rust-backed API surface.
- Keep the bitcoinjs cross-check harness independent of the Rust implementation. `test-vectors/cross-check.json` should describe inputs only; derived keys, addresses, and WIFs must be computed fresh by both engines.
- Do not add APIs that imply seed phrases can be recovered from xprivs. BIP39 seed phrase to xpriv is one-way.
- Keep secret material out of logs, test names, panic messages, screenshots, and issue comments.
- Prefer deterministic test vectors under `test-vectors/` for parity behavior.
- Update `docs/API.md`, `docs/SECURITY_MODEL.md`, and `CHANGELOG.md` when public behavior changes.

## Pull Request Checklist

- `./scripts/verify.sh` passes locally.
- New public behavior has tests.
- The README or docs describe any new public API.
- No generated build outputs, local caches, or native binaries are included unless part of a documented release artifact.
- Security-relevant changes explain the threat model and user-visible impact.
