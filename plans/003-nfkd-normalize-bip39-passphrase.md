# Plan 003: NFKD-normalize BIP39 passphrases before seed derivation

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md` — unless a reviewer dispatched you and told you they
> maintain the index.
>
> **Drift check (run first)**:
> `git diff --stat 32f1e4d..HEAD -- crates/easydoge-km/src/keys.rs crates/easydoge-km/tests/parity.rs test-vectors/cross-check.json docs/API.md docs/SECURITY_MODEL.md CHANGELOG.md`
> If any in-scope file changed since this plan was written, compare the
> "Current state" excerpts against the live code before proceeding; on a
> mismatch, treat it as a STOP condition. (`parity.rs`, `CHANGELOG.md`, and
> `docs/SECURITY_MODEL.md` are also touched by plans 001/002 — additive
> changes there are expected and fine.)

## Status

- **Priority**: P1
- **Effort**: S
- **Risk**: HIGH (derivation output changes for passphrases that are not already NFKD-normalized — see "Compatibility decision")
- **Depends on**: none
- **Category**: bug (spec compliance with fund-safety impact)
- **Planned at**: commit `32f1e4d`, 2026-09-04
- **Audit finding**: #2 (deep audit, evidence originally collected at `04e7499`, revalidated at `32f1e4d`)

## Why this matters

BIP39 requires both the mnemonic and the passphrase to be NFKD-normalized
before PBKDF2. The core normalizes the phrase but passes the passphrase raw to
`Mnemonic::to_seed_normalized`, whose contract (verified in the `bip39 2.2.2`
source) is that the caller has already normalized it. Two canonically equal
passphrases such as `café` typed as `U+00E9` versus `e` + `U+0301` therefore
derive different wallets, and any non-ASCII passphrase derives a wallet that no
standard BIP39 implementation (including this repo's own bitcoinjs cross-check)
can reproduce. Users who restore such a wallet elsewhere see an empty balance.

## Compatibility decision (made by the advisor; executor does not re-decide)

- **Decision**: make the SDK spec-compliant. Normalize passphrases with NFKD
  everywhere seeds are derived. Do **not** add a "legacy non-normalized" mode.
- **Rationale**: this is a `0.x` SDK; the buggy derivations were incompatible
  with every other BIP39 wallet, so keeping them preserves an incompatible
  wallet rather than a user-visible feature. ASCII passphrases (the only
  documented ones, e.g. `TREZOR`) and empty passphrases are byte-identical
  under NFKD and are unaffected.
- **Migration**: document in `CHANGELOG.md` that wallets created through this
  SDK with non-NFKD passphrases (precomposed accents, fullwidth or
  compatibility characters, ideographic spaces) will derive different keys, and
  that affected users must sweep funds from the old derivation using a build
  from before this change. If the operator wants a legacy escape hatch instead,
  that is a STOP condition — report back rather than adding one.

## Current state

- `crates/easydoge-km/src/keys.rs` — mnemonic and seed APIs.
  - `normalize` (lines 390–392) already performs NFKD via `unicode_normalization` and is used for phrases in `validate_mnemonic` (184) and `parse_mnemonic` (385).
  - `mnemonic_to_seed_hex` (188–196) and `account_xpriv_from_mnemonic` (198–230) call `mnemonic.to_seed_normalized(passphrase.unwrap_or_default())` with the raw passphrase.
- `crates/easydoge-km/Cargo.toml` — `bip39` with features `all-languages, rand, zeroize` plus default `std` (which enables `unicode-normalization`); `unicode-normalization` is a direct dependency too. No manifest change needed.
- `crates/easydoge-km/tests/parity.rs` — integration tests; `PHRASE` constant is the 12-word `abandon … about` mnemonic; passphrase `TREZOR` is used throughout.
- `test-vectors/cross-check.json` — input-only fixture consumed by both `crates/easydoge-km/examples/cross_check_vectors.rs` and `tools/bitcoinjs-cross-check/cross-check.mjs`. bitcoinjs's `bip39.mnemonicToSeedSync(phrase, passphrase)` NFKD-normalizes the passphrase, so adding a non-NFKD passphrase case makes the harness fail today and pass after the fix.
- Reference vector (BIP39 Japanese vectors, copied from `bip39 2.2.2` `src/lib.rs` test `test_vectors_japanese`, first entry): mnemonic = eleven × `あいこくしん` followed by `あおぞら`, words separated by the ideographic space `U+3000`; passphrase `㍍ガバヴァぱばぐゞちぢ十人十色` (starts with the compatibility character `U+334D`); expected seed hex `a262d6fb6122ecf45be09c50492b31f92e9beb7d9a845987a02cefda57a15f9c467a17872029a9e92299b5cbdf306e3a0ee620245cbd508959b6cb7ca637bd55`.

Excerpt, `crates/easydoge-km/src/keys.rs:188-196` (today):

```rust
pub fn mnemonic_to_seed_hex(
    phrase: &str,
    passphrase: Option<&str>,
    language: Language,
) -> Result<String> {
    let mnemonic = parse_mnemonic(phrase, language)?;
    let seed = mnemonic.to_seed_normalized(passphrase.unwrap_or_default());
    Ok(hex::encode(seed))
}
```

Excerpt, `crates/easydoge-km/src/keys.rs:205-206` (today):

```rust
    let mnemonic = parse_mnemonic(phrase, language)?;
    let seed = mnemonic.to_seed_normalized(passphrase.unwrap_or_default());
```

Excerpt, `crates/easydoge-km/src/keys.rs:390-392` (today):

```rust
pub(crate) fn normalize(value: &str) -> String {
    value.nfkd().collect::<Cow<'_, str>>().to_string()
}
```

Conventions: `CONTEXT.md` terms "Seed Phrase", "BIP39 Seed"; `CONTRIBUTING.md` requires TDD and doc updates; `scripts/check-open-source-ready.sh` fails on the uppercase "to do"/"fix me" marker words anywhere in the repo, so do not write them.

## Commands you will need

| Purpose | Command | Expected on success |
|---------|---------|---------------------|
| Format check | `cargo fmt --all --check` | exit 0 |
| Run one test | `cargo test -p easydoge-km --test parity <test_name>` | `test result: ok` |
| Core tests | `cargo test -p easydoge-km --locked` | all pass |
| Cross-check | `bash scripts/cross-check.sh` | exit 0 and no diff reported (needs Node 20, pnpm) |
| Clippy | `cargo clippy --workspace --all-targets -- -D warnings` | exit 0 |
| Full suite | `./scripts/verify.sh` | exit 0 |

## Suggested executor toolkit

- `tdd` skill, if available.

## Scope

**In scope** (the only files you should modify):

- `crates/easydoge-km/src/keys.rs`
- `crates/easydoge-km/tests/parity.rs`
- `test-vectors/cross-check.json`
- `docs/API.md`, `docs/SECURITY_MODEL.md`, `CHANGELOG.md`

**Out of scope** (do NOT touch):

- `test-vectors/parity.json` — the committed parity vectors use the ASCII passphrase `TREZOR` and must not change.
- `tools/bitcoinjs-cross-check/**` — the independent harness already normalizes; it must stay untouched so it remains an independent oracle (ADR 0004).
- CLI/TUI passphrase prompts, FFI, Swift/Kotlin/Expo — they pass the passphrase through to the core and inherit the fix.
- Any "legacy derivation" flag or API.

## Git workflow

- Branch: `fix/bip39-passphrase-nfkd`
- Conventional Commits, e.g. `fix(keys): NFKD-normalize BIP39 passphrases before seed derivation`
- Do NOT push or open a PR unless the operator instructed it.

## Steps

### Step 1: Add the failing cross-check case (independent oracle)

Edit `test-vectors/cross-check.json`:

1. Append to `"mnemonics"`:

```json
    {
      "id": "abandon-unicode-passphrase",
      "language": "english",
      "phrase": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
      "passphrase": "caf\u00e9\uff21"
    }
```

Write the `\u00e9` (precomposed e-acute) and `\uff21` (fullwidth A) JSON escapes literally so an editor cannot silently re-normalize them.

2. Append to `"bip44_cases"`:

```json
    {
      "id": "mainnet-account-0-unicode-passphrase",
      "mnemonic_id": "abandon-unicode-passphrase",
      "network": "mainnet",
      "account": 0,
      "child_paths": ["m/0/0"],
      "hardened_public_path": "m/0'/0"
    }
```

**Verify**: `bash scripts/cross-check.sh` → exits **non-zero** and the comparison reports a mismatch for `abandon-unicode-passphrase` / `mainnet-account-0-unicode-passphrase` (this proves the bug with an independent implementation). If it exits 0 here, STOP: either the harness does not normalize or the bug is already fixed.

### Step 2: Add the failing Rust tests

Append to `crates/easydoge-km/tests/parity.rs`:

```rust
#[test]
fn seed_derivation_normalizes_passphrase_to_nfkd() {
    let precomposed = mnemonic_to_seed_hex(PHRASE, Some("caf\u{00e9}"), Language::English).unwrap();
    let decomposed =
        mnemonic_to_seed_hex(PHRASE, Some("cafe\u{0301}"), Language::English).unwrap();
    let plain = mnemonic_to_seed_hex(PHRASE, Some("cafe"), Language::English).unwrap();
    assert_eq!(precomposed, decomposed);
    assert_ne!(precomposed, plain);

    let fullwidth = mnemonic_to_seed_hex(PHRASE, Some("\u{ff21}"), Language::English).unwrap();
    let ascii = mnemonic_to_seed_hex(PHRASE, Some("A"), Language::English).unwrap();
    assert_eq!(fullwidth, ascii, "NFKD maps fullwidth A to ASCII A");
}

#[test]
fn account_keys_normalize_passphrase_to_nfkd() {
    let precomposed = account_xpriv_from_mnemonic(
        PHRASE,
        Some("caf\u{00e9}"),
        Language::English,
        Network::Mainnet,
        0,
    )
    .unwrap();
    let decomposed = account_xpriv_from_mnemonic(
        PHRASE,
        Some("cafe\u{0301}"),
        Language::English,
        Network::Mainnet,
        0,
    )
    .unwrap();
    assert_eq!(precomposed.xpub.encoded, decomposed.xpub.encoded);
}

#[test]
fn japanese_bip39_reference_vector_with_compatibility_passphrase_matches_spec() {
    let words = ["あいこくしん"; 11]
        .iter()
        .chain(std::iter::once(&"あおぞら"))
        .copied()
        .collect::<Vec<_>>()
        .join("\u{3000}");
    let seed = mnemonic_to_seed_hex(
        &words,
        Some("㍍ガバヴァぱばぐゞちぢ十人十色"),
        Language::Japanese,
    )
    .unwrap();
    assert_eq!(
        seed,
        "a262d6fb6122ecf45be09c50492b31f92e9beb7d9a845987a02cefda57a15f9c467a17872029a9e92299b5cbdf306e3a0ee620245cbd508959b6cb7ca637bd55"
    );
}
```

**Verify**: `cargo test -p easydoge-km --test parity passphrase` and `cargo test -p easydoge-km --test parity japanese_bip39` → all three **fail** (`assert_eq` mismatches).

### Step 3: Normalize the passphrase in both seed paths

In `crates/easydoge-km/src/keys.rs`, change both call sites (lines 194 and 206) from

```rust
    let seed = mnemonic.to_seed_normalized(passphrase.unwrap_or_default());
```

to

```rust
    let seed = mnemonic.to_seed_normalized(&normalize(passphrase.unwrap_or_default()));
```

Do not introduce a second normalization helper; reuse the crate's existing `normalize`, which is the same NFKD used for phrases.

**Verify**: `cargo test -p easydoge-km --locked` → all pass, including the three new tests. Existing `mnemonic_derives_account_extended_keys_and_watch_only_address` (passphrase `TREZOR`) must produce the unchanged `parity.json` xpriv/xpub.

### Step 4: Confirm the independent oracle agrees

**Verify**: `bash scripts/cross-check.sh` → exit 0 with no mismatch, including the new `abandon-unicode-passphrase` cases.

### Step 5: Documentation

- `docs/API.md`, section "Non-Reversible Seed Boundary" (or a new short paragraph under "Key and Seed APIs"): "Seed phrases and passphrases are NFKD-normalized before PBKDF2, as BIP39 requires, so canonically equivalent Unicode input derives the same wallet across every surface and matches other BIP39 implementations."
- `docs/SECURITY_MODEL.md`, "Core Guarantees": add "BIP39 seed phrases and passphrases are NFKD-normalized before seed derivation."
- `CHANGELOG.md`, `## [Unreleased]`, under `### Security` (create the heading if plans 001/002 have not): "BIP39 passphrases are now NFKD-normalized before PBKDF2, matching the BIP39 specification and the bitcoinjs cross-check. Wallets previously derived through EasyDoge KM with a passphrase containing non-NFKD characters (precomposed accented letters, fullwidth or compatibility characters, ideographic spaces) will derive different keys after this release; those derivations were not reproducible by other BIP39 wallets. Sweep funds using a pre-release build before upgrading. ASCII and empty passphrases are unaffected."

**Verify**: `bash scripts/check-open-source-ready.sh` → exit 0.

### Step 6: Full verification

**Verify**: `cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace --locked && bash scripts/cross-check.sh` → all exit 0.

## Test plan

- `seed_derivation_normalizes_passphrase_to_nfkd` — canonical (NFD) and compatibility (NFKD) equivalence, plus a negative control.
- `account_keys_normalize_passphrase_to_nfkd` — the account-derivation path uses the same normalization.
- `japanese_bip39_reference_vector_with_compatibility_passphrase_matches_spec` — external reference vector from the BIP39 Japanese test set (also embedded in the `bip39` crate's own tests).
- Cross-check case `abandon-unicode-passphrase` — independent bitcoinjs oracle (fails before, passes after).
- Regression: every existing test that uses `TREZOR` or an empty passphrase must produce identical output.

## Done criteria

Machine-checkable. ALL must hold:

- [ ] `grep -n "to_seed_normalized(passphrase" crates/easydoge-km/src/keys.rs` returns no matches
- [ ] `grep -c "to_seed_normalized(&normalize(" crates/easydoge-km/src/keys.rs` → `2`
- [ ] `cargo test --workspace --locked` exits 0 and lists the three new tests
- [ ] `bash scripts/cross-check.sh` exits 0 and `grep -c unicode-passphrase test-vectors/cross-check.json` → `3` (one mnemonic id, one case id, one `mnemonic_id` reference)
- [ ] `grep -n "NFKD" CHANGELOG.md docs/SECURITY_MODEL.md docs/API.md` → at least one match in each file
- [ ] `test-vectors/parity.json` is unchanged (`git diff --quiet 32f1e4d -- test-vectors/parity.json`)
- [ ] `git status --porcelain` lists only in-scope files
- [ ] `plans/README.md` status row updated

## STOP conditions

Stop and report back (do not improvise) if:

- Step 1's cross-check does **not** fail before the fix (the premise is wrong or the harness changed).
- The Japanese reference vector still fails after Step 3 while the bitcoinjs cross-check passes (would indicate a phrase-normalization or wordlist problem outside this plan's scope).
- The parity `TREZOR` vectors change in any way.
- The operator asks for a legacy (non-normalized) derivation mode — that is a product decision that must be recorded as an ADR first.
- `normalize` in `keys.rs` no longer performs NFKD (drift).

## Maintenance notes

- Any future API that accepts a passphrase (for example a handle-based derivation API for Expo) must route through the same `normalize` call; add a test in the style of `seed_derivation_normalizes_passphrase_to_nfkd` for each new entry point.
- The `bip39` crate offers `Mnemonic::to_seed(passphrase)` which normalizes internally; the repo deliberately keeps normalization explicit and local so the behavior is visible and testable in one place.
- Reviewer focus: confirm the CHANGELOG migration note is present — this is a silent key-derivation change for affected users.
