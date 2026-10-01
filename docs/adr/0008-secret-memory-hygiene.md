# ADR 0008: Best-Effort Wiping of Rust-Owned Secret Memory

## Status

Accepted

## Context

Seed phrases, BIP39 seeds, extended private keys, WIFs, and raw private keys pass through the Rust core as ordinary `String`, `Vec<u8>`, and array values. Rust frees such values without overwriting them, so copies stay readable in process memory, core dumps, and swap until the allocator reuses the space. The `zeroize` crate was a declared dependency but was not used.

The SDK is reached through four surfaces with different memory ownership: Rust callers, the UniFFI-generated Swift and Kotlin bindings, the Expo bridge on top of those, and the CLI/TUI. UniFFI copies values across the boundary in `RustBuffer`s. A top-level `String` argument arrives as a buffer that becomes the Rust `String` without another copy. An `Option<String>` or record argument arrives serialized; UniFFI copies each field out and frees the serialized buffer itself. Return values are serialized from plain Rust values, which UniFFI frees, into a buffer that the foreign side later hands back to be freed. None of those UniFFI-owned frees overwrite memory, and a `#[derive(uniffi::Record)]` struct cannot implement `Drop`, because the generated serialization code moves its fields out.

## Decision

The SDK wipes secret memory that Rust code in this workspace owns, on a best-effort basis, and states what it cannot wipe. Whoever allocates a copy is responsible for it.

The SDK wipes:

- Temporaries inside the Rust core. Normalized seed phrases and passphrases, the 64-byte BIP39 seed, Base58Check payloads of extended keys and WIFs, raw private-key bytes, and WIF text held by the Compose-and-Sign Transaction Builder live in `zeroize::Zeroizing` buffers. Decoded extended private keys and WIF keys are held in wrapper types (`ErasingXpriv`, `WifKey`) that erase the private key, and the chain code, when dropped, because the underlying `secp256k1` and `bitcoin` types are `Copy` and have no destructor. Buffers are sized before they are filled where that is cheap, so they are not reallocated.
- Secret-bearing records of the Rust API. `Xpriv`, `GeneratedMnemonic`, and `UtxoSigner` implement `Zeroize` and `ZeroizeOnDrop`. Records that contain them (`AccountKeySet`, `ChangeDestination`, `SpendableUtxo`, `ComposeTransactionRequest`) are wiped through those fields when dropped. Field types stay `String` so serde, `Clone`, equality, and the FFI conversions keep their shape.
- FFI arguments once they are Rust values. Exported functions wrap `phrase`, `passphrase`, and `wif` parameters in `Zeroizing` on entry, and convert record arguments into core records by moving their strings, so the core record's destructor wipes them.
- The TUI session. The Key Source, a pending seed phrase, and the input and passphrase buffers are wiped when they are cleared, replaced, or the session ends.

The SDK does not wipe, and does not claim to:

- Strings and objects owned by Swift, Kotlin, or JavaScript, including the arguments a caller passed and the values the bindings return.
- UniFFI-owned memory: serialized argument buffers for records and optional strings, the plain FFI records and strings consumed while a return value is serialized, the return buffers themselves, and the record copy UniFFI lifts when `toString()` or `debugDescription` is called on a secret-bearing record.
- Values returned to the caller by API design: seed hex, WIF text, xpriv text, mnemonic text, and signatures. Rust callers own them and may wrap them in `Zeroizing`.
- Copies made by moves, by `String` or `Vec` reallocation outside the sized buffers, by `serde` and `serde_json`, by `Clone` of a record (each clone wipes itself, but the caller decides how many exist), and state inside `bip39`, `bitcoin`, `secp256k1`, `bs58`, `hex`, and the hash implementations.
- One-shot CLI commands, whose arguments are already exposed through the process arguments or a file and whose process exits immediately, and anything the TUI has drawn after the user chose to reveal it.

Alternatives not adopted: a secret-string type for public fields (breaks the Rust API and changes the generated bindings for a gain limited to Rust callers); hand-written UniFFI converters or custom types for secret fields (couples the crate to UniFFI internals and still leaves return values unwiped); a zeroizing global allocator in the FFI library (would cover UniFFI's frees, but imposes an allocator on every consumer of the crate and needs its own performance and compatibility evaluation); memory locking or guard pages.

## Consequences

Secrets exist in fewer Rust-side copies for a shorter time, and long-lived Rust copies such as a retained `ComposeTransactionRequest` are wiped when dropped. This is hygiene, not a guarantee: anything that can read the process's memory while a call is in progress, or the foreign runtime's heap at any time, can still read secrets.

`Xpriv`, `GeneratedMnemonic`, and `UtxoSigner` now implement `Drop`. Rust callers can no longer move a field out of them, destructure them by value, or use them as the base of struct-update syntax; they take the field with `std::mem::take`, clone it, or borrow it. The Swift, Kotlin, and Expo APIs and the generated bindings are unchanged.

Wiping at drop cannot be observed by a safe test, because reading freed memory is undefined behavior. Tests pin the trait implementations and the effect of an explicit `zeroize()`; review and text-search checks cover the internal buffers. New code that handles secrets follows the same rules: hold secret text or bytes in `Zeroizing`, hold keys in the erasing wrappers, and never add a plain `String` secret field to a record that has no wiping destructor.
