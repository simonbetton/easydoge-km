# Plan 002: Authenticate Signing Envelopes before signing, combining, or finalizing

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md` — unless a reviewer dispatched you and told you they
> maintain the index.
>
> **Drift check (run first)**:
> `git diff --stat 32f1e4d..HEAD -- crates/easydoge-km/src/signing.rs crates/easydoge-km/src/transaction_builder.rs crates/easydoge-km/tests/parity.rs docs/API.md docs/SECURITY_MODEL.md CHANGELOG.md`
> Plan 001 is expected to have touched `signing.rs`, `transaction_builder.rs`,
> `parity.rs`, and the docs. Confirm plan 001 is DONE in `plans/README.md`,
> then compare the "Current state" excerpts below (which describe the code
> *after* plan 001) against the live code; on a mismatch, treat it as a STOP
> condition.

## Status

- **Priority**: P1
- **Effort**: M
- **Risk**: MED (stricter inputs: envelopes that used to finalize with junk signatures or mismatched scripts now error)
- **Depends on**: `plans/001-restrict-sighash-types.md`
- **Category**: security
- **Planned at**: commit `32f1e4d`, 2026-09-04
- **Audit finding**: #1 (deep audit, evidence originally collected at `04e7499`, revalidated at `32f1e4d`)
- **Amended**: 2026-09-06 at `599ca98` by the reviewer before dispatch. The validator now retains, rather than rejects, signatures for inputs that a partial envelope does not describe, because the transaction builder signs one input at a time while carrying the signatures already collected for earlier inputs (see Step 1 notes). Two guard tests were added: `signing_envelope_keeps_signatures_for_inputs_it_does_not_describe` and `compose_builder_signs_every_input_of_a_multi_utxo_transaction`.

## Why this matters

A Signing Envelope is the portable trust boundary between co-signers, and the
core currently trusts everything inside it. `sign_signing_envelope` signs every
input with whatever WIF it is given, even inputs the key cannot spend.
`finalize_signing_envelope` never verifies a signature: the existing tests
finalize with `signature_hex: "aa"`, and the P2SH script pubkey in those tests
does not even hash to the redeem script. It also finalizes transactions whose
inputs are only partially described, leaving empty scriptSigs. A malicious or
buggy co-signer can therefore inject garbage that only fails at broadcast, or
trick a wallet into producing a transaction with a redeem script that does not
match the output being spent. After this plan every envelope entry point
validates structure, script consistency, key ownership, and signature validity
against the actual sighash before it does anything else.

## Current state

Line numbers below were taken at `32f1e4d` before plan 001 landed. Plan 001
added `validate_sighash_type` and `validated_sighash_flag` near the top of
`signing.rs` (live lines 18–46), so live positions in that file are offset by
about 35 lines: `sign_signing_envelope` now starts at live line 120,
`combine_signing_envelopes` at 155, and `finalize_signing_envelope` at 183.
The builder's per-input signing loop is at live lines 283–297 of
`transaction_builder.rs`. The reviewer confirmed at `599ca98` that every
excerpt below matches the live code by content. Match on content, not on
line numbers; a content mismatch is still a STOP condition.

- `crates/easydoge-km/src/signing.rs` — `SigningEnvelope` DTOs (lines 13–55), `sign_p2pkh_transaction` (57–83, builds a one-input envelope, signs it, then calls `finalize_signing_envelope`), `sign_signing_envelope` (85–116), `combine_signing_envelopes` (118–144), `finalize_signing_envelope` (146–232), helpers `parse_transaction`, `parse_script`, `push_bytes`, `MultisigMetadata`, `multisig_metadata`, `parse_multisig_redeem_script`, `decode_pushnum` (234–347). Plan 001 added `validate_sighash_type` and `validated_sighash_flag` (`pub(crate)`).
- `crates/easydoge-km/src/transaction_builder.rs` — the builder calls `sign_signing_envelope` once per resolved signer with a **single-input** envelope even for multi-input transactions (lines 279–292) and `finalize_signing_envelope` with the full envelope when `envelope_is_complete` (295–299). It already checks signer ownership for its own signers (`validate_signer_ownership`, 669–711) — that logic stays; the envelope layer must now enforce the same thing for external callers. Because the builder signs with partial envelopes, **signing must accept envelopes that describe only some inputs; only finalization requires every input to be described.**
- `crates/easydoge-km/src/encoding.rs` — `pub(crate) fn hash160_bytes(bytes: &[u8]) -> [u8; 20]` (line 6). Reuse it.
- `crates/easydoge-km/tests/parity.rs` — tests `p2sh_multisig_finalize_requires_threshold_signatures` (lines 300–341) and `p2sh_multisig_finalize_uses_redeem_script_public_key_order` (343–394) use fake signatures `"01"`, `"aa"`, `"bb"` and the script pubkey `a914000…0087`. Both must be rewritten (Step 2).
- `test-vectors/parity.json` — `mnemonic.phrase` + passphrase `TREZOR`; `transaction.unsigned_tx_hex` (1 input, 1 output) and `transaction.script_pubkey_hex` belong to the account WIF (`hash160(027740a1…) == 6dcc18cf…`, verified). The `multisig.cosigner_xpubs` are NOT derivable from the parity mnemonic, so real multisig signing tests must build their own 2-of-2 from accounts 0 and 1 of the parity mnemonic (Step 2 shows how).

Excerpt, `signing.rs:146-160` (finalize, today):

```rust
pub fn finalize_signing_envelope(envelope: &SigningEnvelope) -> Result<SignedTransaction> {
    let mut tx = parse_transaction(&envelope.unsigned_tx_hex)?;
    for input in &envelope.inputs {
        validated_sighash_flag(input.sighash_type, input.input_index, tx.output.len())?; // plan 001
        let mut matching: Vec<&SigningEnvelopeSignature> = envelope
            .signatures
            .iter()
            .filter(|signature| signature.input_index == input.input_index)
            .collect();
        matching.sort_by_key(|signature| signature.public_key_hex.as_str());
        if matching.is_empty() {
            return Err(Error::InvalidTransaction(format!(
                "input {} has no signatures",
                input.input_index
            )));
        }
```

Excerpt, `signing.rs:85-90` (sign, today):

```rust
pub fn sign_signing_envelope(envelope: &SigningEnvelope, wif: &str) -> Result<SigningEnvelope> {
    let secret_key = secret_key_from_wif(wif, envelope.network)?;
    let secp = Secp256k1::new();
    let public_key = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &secret_key);
    let tx = parse_transaction(&envelope.unsigned_tx_hex)?;
    let mut signatures = envelope.signatures.clone();
```

Excerpt, `signing.rs:118-132` (combine, today): compares `version`, `network`, `unsigned_tx_hex`, `inputs` for equality and unions signatures by exact `(input_index, public_key_hex, signature_hex)` — no verification.

Repo conventions:

- `crate::Error` variants; use `Error::InvalidTransaction` for structural/signature problems and `Error::InvalidKey` for "this WIF controls nothing".
- Public keys are always 33-byte compressed hex; the SDK does not support uncompressed keys (finding 11 is a separate, deferred item).
- Tests in `crates/easydoge-km/tests/parity.rs`, assertions on `error.to_string().contains(...)`.
- ADR 0005 (`docs/adr/0005-offline-compose-and-sign-builder.md`): "validates signer ownership, signs selected inputs, and returns either signed transaction hex or a signing envelope". This plan extends the same guarantee to envelopes supplied by external callers.
- `scripts/check-open-source-ready.sh` fails on the uppercase "to do"/"fix me" marker words anywhere in the repo. Do not write them.

## Commands you will need

| Purpose | Command | Expected on success |
|---------|---------|---------------------|
| Format check | `cargo fmt --all --check` | exit 0 |
| Run one test | `cargo test -p easydoge-km --test parity <test_name>` | `test result: ok` |
| Core tests | `cargo test -p easydoge-km --locked` | all pass |
| Workspace tests | `cargo test --workspace --locked` | all pass |
| Clippy | `cargo clippy --workspace --all-targets -- -D warnings` | exit 0 |
| Cross-check | `bash scripts/cross-check.sh` | exit 0 |
| Bindings + native tests | `./scripts/generate-bindings.sh && (cd bindings/swift && swift test) && (cd bindings/kotlin && ./gradlew test)` | all pass (Swift 6, JDK 17 required) |
| Full suite | `./scripts/verify.sh` | exit 0 |

## Suggested executor toolkit

- `tdd` skill, if available: Step 2 writes the failing tests, Steps 3–6 make them pass.

## Scope

**In scope** (the only files you should modify):

- `crates/easydoge-km/src/signing.rs`
- `crates/easydoge-km/tests/parity.rs`
- `docs/API.md`, `docs/SECURITY_MODEL.md`, `CHANGELOG.md`

**Out of scope** (do NOT touch, even though they look related):

- `crates/easydoge-km/src/transaction_builder.rs` — its own ownership checks stay; it must keep compiling against the unchanged public signatures of `sign_signing_envelope` / `finalize_signing_envelope`. If you believe it must change, STOP.
- `crates/easydoge-km-ffi`, Swift/Kotlin/Expo bindings, CLI — no type or signature changes in this plan.
- Duplicate-key multisig descriptors (finding 12), uncompressed keys (finding 11), resource caps on envelope size (finding 17).

## Git workflow

- Branch: `fix/authenticate-signing-envelopes`
- Conventional Commits, e.g. `fix(signing): verify ownership and signatures in signing envelopes`
- Do NOT push or open a PR unless the operator instructed it.

## Steps

### Step 1: Add the envelope validator (no callers yet)

In `crates/easydoge-km/src/signing.rs` add imports:

```rust
use bitcoin::secp256k1::ecdsa::Signature;
use bitcoin::secp256k1::PublicKey;
use crate::encoding::hash160_bytes;
```

Add these private types and functions (place them after `finalize_signing_envelope`, before `parse_transaction`):

```rust
/// Whether an envelope must describe every transaction input.
#[derive(Clone, Copy, PartialEq, Eq)]
enum DescriptorCoverage {
    /// Signing and combining: a co-signer may only know about some inputs.
    Partial,
    /// Finalizing: every input needs a scriptSig.
    Complete,
}

/// One envelope input after structural validation.
struct ValidatedInput<'a> {
    descriptor: &'a SigningEnvelopeInput,
    /// Script committed to by the legacy sighash: the script pubkey for
    /// P2PKH, the redeem script for P2SH multisig.
    signing_script: bitcoin::ScriptBuf,
    /// 20-byte pubkey hash for P2PKH inputs.
    pubkey_hash: Option<[u8; 20]>,
    sighash_flag: u8,
    multisig: Option<MultisigMetadata>,
}

impl ValidatedInput<'_> {
    fn index(&self) -> usize {
        self.descriptor.input_index
    }

    fn controls(&self, public_key: &PublicKey) -> bool {
        match (&self.pubkey_hash, &self.multisig) {
            (Some(hash), _) => hash160_bytes(&public_key.serialize()) == *hash,
            (None, Some(metadata)) => {
                let hex = hex::encode(public_key.serialize());
                metadata
                    .public_keys_hex
                    .iter()
                    .any(|key| key.eq_ignore_ascii_case(&hex))
            }
            (None, None) => false,
        }
    }
}

/// Validates envelope structure, script consistency, and every present
/// signature. Returns inputs sorted by transaction input index.
fn validate_envelope<'a>(
    envelope: &'a SigningEnvelope,
    tx: &Transaction,
    coverage: DescriptorCoverage,
) -> Result<Vec<ValidatedInput<'a>>> {
    if envelope.version != 1 {
        return Err(Error::InvalidTransaction(format!(
            "unsupported signing envelope version {}",
            envelope.version
        )));
    }
    let mut descriptors: Vec<&SigningEnvelopeInput> = envelope.inputs.iter().collect();
    descriptors.sort_by_key(|input| input.input_index);
    if let Some(pair) = descriptors
        .windows(2)
        .find(|pair| pair[0].input_index == pair[1].input_index)
    {
        return Err(Error::InvalidTransaction(format!(
            "signing envelope describes input {} more than once",
            pair[0].input_index
        )));
    }
    if let Some(out_of_range) = descriptors
        .iter()
        .find(|input| input.input_index >= tx.input.len())
    {
        return Err(Error::InvalidTransaction(format!(
            "signing envelope input index {} out of range (transaction has {} inputs)",
            out_of_range.input_index,
            tx.input.len()
        )));
    }
    if coverage == DescriptorCoverage::Complete && descriptors.len() != tx.input.len() {
        return Err(Error::InvalidTransaction(format!(
            "signing envelope must describe every transaction input (transaction has {} inputs, envelope describes {})",
            tx.input.len(),
            descriptors.len()
        )));
    }

    let mut validated = Vec::with_capacity(descriptors.len());
    for descriptor in descriptors {
        let index = descriptor.input_index;
        let script_pubkey = parse_script(&descriptor.script_pubkey_hex)?;
        let sighash_flag =
            validated_sighash_flag(descriptor.sighash_type, index, tx.output.len())?;
        let input = match descriptor.kind {
            SigningInputKind::P2pkh => {
                if descriptor.redeem_script_hex.is_some() {
                    return Err(Error::InvalidTransaction(format!(
                        "P2PKH input {index} must not include a redeem script"
                    )));
                }
                let bytes = script_pubkey.as_bytes();
                let is_p2pkh = bytes.len() == 25
                    && bytes[0..3] == [0x76, 0xa9, 0x14]
                    && bytes[23..25] == [0x88, 0xac];
                if !is_p2pkh {
                    return Err(Error::InvalidTransaction(format!(
                        "P2PKH input {index} script pubkey is not a pay-to-pubkey-hash script"
                    )));
                }
                let mut hash = [0u8; 20];
                hash.copy_from_slice(&bytes[3..23]);
                ValidatedInput {
                    descriptor,
                    signing_script: script_pubkey,
                    pubkey_hash: Some(hash),
                    sighash_flag,
                    multisig: None,
                }
            }
            SigningInputKind::P2shMultisig => {
                let redeem_script_hex = descriptor.redeem_script_hex.as_deref().ok_or_else(|| {
                    Error::InvalidTransaction(format!(
                        "P2SH multisig input {index} requires redeem script"
                    ))
                })?;
                let redeem_script = parse_script(redeem_script_hex)?;
                let mut expected = Vec::with_capacity(23);
                expected.extend_from_slice(&[0xa9, 0x14]);
                expected.extend_from_slice(&hash160_bytes(redeem_script.as_bytes()));
                expected.push(0x87);
                if script_pubkey.as_bytes() != expected.as_slice() {
                    return Err(Error::InvalidTransaction(format!(
                        "P2SH input {index} script pubkey does not match redeem script"
                    )));
                }
                let metadata = multisig_metadata(descriptor, redeem_script_hex)?;
                ValidatedInput {
                    descriptor,
                    signing_script: redeem_script,
                    pubkey_hash: None,
                    sighash_flag,
                    multisig: Some(metadata),
                }
            }
        };
        validated.push(input);
    }

    let secp = Secp256k1::verification_only();
    let cache = SighashCache::new(tx);
    for signature in &envelope.signatures {
        let index = signature.input_index;
        let input = match validated.iter().find(|input| input.index() == index) {
            Some(input) => input,
            None if index >= tx.input.len() => {
                return Err(Error::InvalidTransaction(format!(
                    "signature references input {index} which is out of range (transaction has {} inputs)",
                    tx.input.len()
                )));
            }
            // Only reachable under Partial coverage, because Complete coverage
            // describes every in-range input. A co-signer, or the transaction
            // builder (which signs one input at a time while carrying the
            // signatures already collected for other inputs), may hold
            // signatures for inputs this envelope does not describe. They cannot
            // be verified here because the signing script is unknown; they are
            // verified at finalization, which requires every input described.
            None => continue,
        };
        let public_key_bytes = hex::decode(&signature.public_key_hex)
            .map_err(|err| Error::Serialization(format!("invalid public key hex: {err}")))?;
        let public_key = PublicKey::from_slice(&public_key_bytes).map_err(|_| {
            Error::InvalidTransaction(format!(
                "signature for input {index} has an invalid public key"
            ))
        })?;
        if public_key_bytes.len() != 33 || !input.controls(&public_key) {
            return Err(Error::InvalidTransaction(format!(
                "signature for input {index} was made by a key that does not control the input"
            )));
        }
        let signature_bytes = hex::decode(&signature.signature_hex)
            .map_err(|err| Error::Serialization(format!("invalid signature hex: {err}")))?;
        let (der, flag) = match signature_bytes.split_last() {
            Some((flag, der)) if !der.is_empty() => (der, *flag),
            _ => {
                return Err(Error::InvalidTransaction(format!(
                    "signature for input {index} is empty"
                )))
            }
        };
        if flag != input.sighash_flag {
            return Err(Error::InvalidTransaction(format!(
                "signature for input {index} uses sighash type {flag:#x} but the input requires {:#x}",
                input.sighash_flag
            )));
        }
        let parsed = Signature::from_der(der).map_err(|_| {
            Error::InvalidTransaction(format!("signature for input {index} is not valid DER"))
        })?;
        let sighash = cache
            .legacy_signature_hash(
                index,
                input.signing_script.as_script(),
                input.descriptor.sighash_type,
            )
            .map_err(|err| Error::Crypto(err.to_string()))?;
        let message = Message::from_digest(sighash.to_byte_array());
        if secp.verify_ecdsa(&message, &parsed, &public_key).is_err() {
            return Err(Error::InvalidTransaction(format!(
                "signature for input {index} does not verify against the transaction"
            )));
        }
    }
    Ok(validated)
}
```

Notes: `multisig_metadata` keeps returning an owned `MultisigMetadata`, which is moved into `ValidatedInput`. If `Secp256k1::verification_only()` is unavailable under the enabled features, use `Secp256k1::new()`. `ValidatedInput` borrows only the envelope, never `tx`, so callers may mutate `tx` after validation.

**Why signatures for undescribed inputs pass through under `Partial` coverage** (do not "tighten" this): `crates/easydoge-km/src/transaction_builder.rs` (live lines 283–297) signs a multi-input transaction one input at a time. For each input it builds a `SigningEnvelope` whose `inputs` holds only that one descriptor but whose `signatures` holds everything collected so far, and passes it to `sign_signing_envelope`. On the second input the envelope therefore carries a signature for input 0 while describing only input 1. Rejecting that signature would break every multi-input transaction the builder produces, and the builder is out of scope. Nothing is lost: `finalize_signing_envelope` uses `Complete` coverage, so every signature is verified before a transaction is produced. Signature indices outside the transaction's input range are rejected under both coverages.

**Verify**: `cargo build -p easydoge-km` → exit 0 (dead-code warnings acceptable until Step 3).

### Step 2: Rewrite the fake-signature tests and add the new ones (failing first)

In `crates/easydoge-km/tests/parity.rs`:

1. Extend the `use easydoge_km::{...}` import with `address_from_wif, combine_signing_envelopes, derive_path_from_xpriv, sign_signing_envelope, MultisigDescriptor` (rustfmt will reorder). Add `use std::collections::HashMap;`. If plan 001 did not add `use bitcoin::consensus::encode::{deserialize, serialize};` and the helpers `parity_unsigned_tx_hex`, `parity_script_pubkey_hex`, `parity_wif`, `two_input_unsigned_tx_hex`, add them exactly as written in `plans/001-restrict-sighash-types.md` Step 2.

2. Add a real 2-of-2 fixture built from accounts 0 and 1 of the parity mnemonic:

```rust
struct TwoOfTwoFixture {
    descriptor: MultisigDescriptor,
    /// WIFs ordered to match `descriptor.public_keys_hex`.
    wifs: Vec<String>,
    envelope: SigningEnvelope,
}

fn two_of_two_fixture(unsigned_tx_hex: &str, input_index: usize) -> TwoOfTwoFixture {
    let accounts = [0u32, 1].map(|account| {
        account_xpriv_from_mnemonic(
            PHRASE,
            Some("TREZOR"),
            Language::English,
            Network::Mainnet,
            account,
        )
        .unwrap()
    });
    let xpubs = accounts
        .iter()
        .map(|account| account.xpub.clone())
        .collect::<Vec<_>>();
    let descriptor =
        create_multisig_descriptor(Network::Mainnet, 2, &xpubs, "m/0/7", true).unwrap();
    let mut wif_by_public_key = accounts
        .iter()
        .map(|account| {
            let child = derive_address_from_xpriv(&account.xpriv, "m/0/7").unwrap();
            let child_xpriv = derive_path_from_xpriv(&account.xpriv, "m/0/7").unwrap();
            (child.public_key_hex, wif_from_xpriv(&child_xpriv).unwrap())
        })
        .collect::<HashMap<_, _>>();
    let wifs = descriptor
        .public_keys_hex
        .iter()
        .map(|key| wif_by_public_key.remove(key).unwrap())
        .collect::<Vec<_>>();
    let redeem_script = hex::decode(&descriptor.redeem_script_hex).unwrap();
    let script_pubkey_hex = format!(
        "a914{}87",
        hex::encode(hash160::Hash::hash(&redeem_script).to_byte_array())
    );
    let envelope = SigningEnvelope {
        version: 1,
        network: Network::Mainnet,
        unsigned_tx_hex: unsigned_tx_hex.to_owned(),
        inputs: vec![SigningEnvelopeInput {
            input_index,
            kind: SigningInputKind::P2shMultisig,
            script_pubkey_hex,
            redeem_script_hex: Some(descriptor.redeem_script_hex.clone()),
            sighash_type: 1,
            previous_output_value_koinu: Some(100_000_000),
            multisig_threshold: Some(2),
            multisig_public_keys_hex: descriptor.public_keys_hex.clone(),
        }],
        signatures: vec![],
    };
    TwoOfTwoFixture {
        descriptor,
        wifs,
        envelope,
    }
}

fn p2pkh_envelope() -> SigningEnvelope {
    SigningEnvelope {
        version: 1,
        network: Network::Mainnet,
        unsigned_tx_hex: parity_unsigned_tx_hex(),
        inputs: vec![SigningEnvelopeInput {
            input_index: 0,
            kind: SigningInputKind::P2pkh,
            script_pubkey_hex: parity_script_pubkey_hex(),
            redeem_script_hex: None,
            sighash_type: 1,
            previous_output_value_koinu: None,
            multisig_threshold: None,
            multisig_public_keys_hex: vec![],
        }],
        signatures: vec![],
    }
}

/// A WIF that controls nothing in the parity fixtures (account 1, m/0/0).
fn foreign_wif() -> String {
    let account =
        account_xpriv_from_mnemonic(PHRASE, Some("TREZOR"), Language::English, Network::Mainnet, 1)
            .unwrap();
    wif_from_xpriv(&derive_path_from_xpriv(&account.xpriv, "m/0/0").unwrap()).unwrap()
}
```

3. Replace `p2sh_multisig_finalize_requires_threshold_signatures` (lines 300–341) with:

```rust
#[test]
fn p2sh_multisig_finalize_requires_threshold_signatures() {
    let fixture = two_of_two_fixture(&parity_unsigned_tx_hex(), 0);
    let partial = sign_signing_envelope(&fixture.envelope, &fixture.wifs[0]).unwrap();
    assert_eq!(partial.signatures.len(), 1);
    let error = finalize_signing_envelope(&partial).unwrap_err();
    assert!(error.to_string().contains("threshold is 2"), "{error}");
}
```

4. Replace `p2sh_multisig_finalize_uses_redeem_script_public_key_order` (lines 343–394) with:

```rust
#[test]
fn p2sh_multisig_finalize_uses_redeem_script_public_key_order() {
    let fixture = two_of_two_fixture(&parity_unsigned_tx_hex(), 0);
    // Sign with the second cosigner first so envelope order differs from redeem-script order.
    let second_first = sign_signing_envelope(&fixture.envelope, &fixture.wifs[1]).unwrap();
    let both = sign_signing_envelope(&second_first, &fixture.wifs[0]).unwrap();
    assert_eq!(both.signatures.len(), 2);
    let signed = finalize_signing_envelope(&both).unwrap();

    let sig_for = |key: &str| {
        both.signatures
            .iter()
            .find(|signature| signature.public_key_hex == key)
            .unwrap()
            .signature_hex
            .clone()
    };
    let first = sig_for(&fixture.descriptor.public_keys_hex[0]);
    let second = sig_for(&fixture.descriptor.public_keys_hex[1]);
    let first_at = signed.signed_tx_hex.find(&first).unwrap();
    let second_at = signed.signed_tx_hex.find(&second).unwrap();
    assert!(first_at < second_at, "signatures must follow redeem script key order");
    assert!(signed.signed_tx_hex.contains(&fixture.descriptor.redeem_script_hex));
}
```

5. Append the new tests:

```rust
#[test]
fn signing_envelope_rejects_wif_that_controls_no_input() {
    let error = sign_signing_envelope(&p2pkh_envelope(), &foreign_wif()).unwrap_err();
    assert!(error.to_string().contains("does not control any input"), "{error}");
}

#[test]
fn sign_p2pkh_transaction_rejects_script_pubkey_not_owned_by_wif() {
    let error = sign_p2pkh_transaction(
        Network::Mainnet,
        &parity_unsigned_tx_hex(),
        0,
        &parity_script_pubkey_hex(),
        &foreign_wif(),
        1,
    )
    .unwrap_err();
    assert!(error.to_string().contains("does not control any input"), "{error}");
}

#[test]
fn sign_p2pkh_transaction_still_signs_one_input_of_a_multi_input_transaction() {
    let signed = sign_p2pkh_transaction(
        Network::Mainnet,
        &two_input_unsigned_tx_hex(),
        0,
        &parity_script_pubkey_hex(),
        &parity_wif(),
        1,
    )
    .unwrap();
    let tx: bitcoin::Transaction =
        deserialize(&hex::decode(&signed.signed_tx_hex).unwrap()).unwrap();
    assert!(!tx.input[0].script_sig.is_empty());
    assert!(tx.input[1].script_sig.is_empty(), "undescribed inputs stay untouched");
}

#[test]
fn signing_envelope_signs_only_inputs_owned_by_each_wif() {
    let unsigned = two_input_unsigned_tx_hex();
    let multisig = two_of_two_fixture(&unsigned, 1);
    let mut envelope = p2pkh_envelope();
    envelope.unsigned_tx_hex = unsigned;
    envelope.inputs.push(multisig.envelope.inputs[0].clone());

    let after_p2pkh = sign_signing_envelope(&envelope, &parity_wif()).unwrap();
    assert_eq!(after_p2pkh.signatures.len(), 1);
    assert_eq!(after_p2pkh.signatures[0].input_index, 0);

    let after_first_cosigner = sign_signing_envelope(&after_p2pkh, &multisig.wifs[0]).unwrap();
    let complete = sign_signing_envelope(&after_first_cosigner, &multisig.wifs[1]).unwrap();
    assert_eq!(complete.signatures.len(), 3);
    assert!(complete.signatures[1..].iter().all(|s| s.input_index == 1));
    finalize_signing_envelope(&complete).unwrap();
}

#[test]
fn signing_envelope_does_not_duplicate_signatures_from_the_same_key() {
    let once = sign_signing_envelope(&p2pkh_envelope(), &parity_wif()).unwrap();
    let twice = sign_signing_envelope(&once, &parity_wif()).unwrap();
    assert_eq!(twice.signatures.len(), 1);
}

#[test]
fn signing_envelope_rejects_duplicate_and_out_of_range_input_descriptors() {
    let mut duplicated = p2pkh_envelope();
    duplicated.inputs.push(duplicated.inputs[0].clone());
    let error = sign_signing_envelope(&duplicated, &parity_wif()).unwrap_err();
    assert!(error.to_string().contains("more than once"), "{error}");

    let mut out_of_range = p2pkh_envelope();
    out_of_range.inputs[0].input_index = 5;
    let error = sign_signing_envelope(&out_of_range, &parity_wif()).unwrap_err();
    assert!(error.to_string().contains("out of range"), "{error}");
}

#[test]
fn finalize_rejects_tampered_signature_bytes() {
    let mut signed = sign_signing_envelope(&p2pkh_envelope(), &parity_wif()).unwrap();
    let mut chars: Vec<char> = signed.signatures[0].signature_hex.chars().collect();
    // Byte 5 sits inside the DER `r` value; changing it keeps DER shape but breaks the math.
    chars[10] = if chars[10] == '0' { '1' } else { '0' };
    signed.signatures[0].signature_hex = chars.into_iter().collect();
    let error = finalize_signing_envelope(&signed).unwrap_err();
    let text = error.to_string();
    assert!(
        text.contains("does not verify") || text.contains("not valid DER"),
        "{text}"
    );
}

#[test]
fn finalize_rejects_signature_with_mismatched_sighash_flag() {
    let mut signed = sign_signing_envelope(&p2pkh_envelope(), &parity_wif()).unwrap();
    let hex_value = &signed.signatures[0].signature_hex;
    assert!(hex_value.ends_with("01"));
    signed.signatures[0].signature_hex = format!("{}81", &hex_value[..hex_value.len() - 2]);
    let error = finalize_signing_envelope(&signed).unwrap_err();
    assert!(error.to_string().contains("uses sighash type"), "{error}");
}

#[test]
fn finalize_rejects_signature_from_key_that_does_not_control_input() {
    let mut signed = sign_signing_envelope(&p2pkh_envelope(), &parity_wif()).unwrap();
    let foreign = address_from_wif(Network::Mainnet, &foreign_wif()).unwrap();
    let foreign_hash =
        hash160::Hash::hash(&hex::decode(foreign.public_key_hex).unwrap()).to_byte_array();
    signed.inputs[0].script_pubkey_hex = format!("76a914{}88ac", hex::encode(foreign_hash));
    let error = finalize_signing_envelope(&signed).unwrap_err();
    assert!(error.to_string().contains("does not control the input"), "{error}");
}

#[test]
fn finalize_rejects_envelope_that_does_not_describe_every_input() {
    let mut envelope = p2pkh_envelope();
    envelope.unsigned_tx_hex = two_input_unsigned_tx_hex();
    // Signing a partial envelope is allowed (co-signers may only know their inputs)...
    let signed = sign_signing_envelope(&envelope, &parity_wif()).unwrap();
    assert_eq!(signed.signatures.len(), 1);
    // ...but finalizing requires every input to be described.
    let error = finalize_signing_envelope(&signed).unwrap_err();
    assert!(error.to_string().contains("every transaction input"), "{error}");
}

#[test]
fn finalize_rejects_p2sh_script_pubkey_that_does_not_match_redeem_script() {
    let mut fixture = two_of_two_fixture(&parity_unsigned_tx_hex(), 0);
    fixture.envelope.inputs[0].script_pubkey_hex =
        "a914000000000000000000000000000000000000000087".to_owned();
    let error = sign_signing_envelope(&fixture.envelope, &fixture.wifs[0]).unwrap_err();
    assert!(error.to_string().contains("does not match redeem script"), "{error}");
}

#[test]
fn p2sh_multisig_cosigners_sign_separately_then_combine_and_finalize() {
    let fixture = two_of_two_fixture(&parity_unsigned_tx_hex(), 0);
    let first = sign_signing_envelope(&fixture.envelope, &fixture.wifs[0]).unwrap();
    let second = sign_signing_envelope(&fixture.envelope, &fixture.wifs[1]).unwrap();
    let combined = combine_signing_envelopes(&[first, second]).unwrap();
    assert_eq!(combined.signatures.len(), 2);
    let signed = finalize_signing_envelope(&combined).unwrap();
    let tx: bitcoin::Transaction =
        deserialize(&hex::decode(&signed.signed_tx_hex).unwrap()).unwrap();
    assert_eq!(tx.input[0].script_sig.as_bytes()[0], 0x00, "OP_0 must lead the scriptSig");
}

#[test]
fn combine_rejects_envelope_carrying_forged_signature() {
    let fixture = two_of_two_fixture(&parity_unsigned_tx_hex(), 0);
    let genuine = sign_signing_envelope(&fixture.envelope, &fixture.wifs[0]).unwrap();
    let mut forged = fixture.envelope.clone();
    forged.signatures.push(SigningEnvelopeSignature {
        input_index: 0,
        public_key_hex: fixture.descriptor.public_keys_hex[1].clone(),
        signature_hex: "300602010102010101".to_owned(),
    });
    let error = combine_signing_envelopes(&[genuine, forged]).unwrap_err();
    assert!(error.to_string().contains("signature for input 0"), "{error}");
}

#[test]
fn signing_envelope_keeps_signatures_for_inputs_it_does_not_describe() {
    // Mirrors the transaction builder, which signs one input at a time while
    // carrying the signatures already collected for other inputs.
    let unsigned = two_input_unsigned_tx_hex();
    let mut first_only = p2pkh_envelope();
    first_only.unsigned_tx_hex = unsigned.clone();
    let after_first = sign_signing_envelope(&first_only, &parity_wif()).unwrap();
    assert_eq!(after_first.signatures.len(), 1);

    let mut second_only = p2pkh_envelope();
    second_only.unsigned_tx_hex = unsigned;
    second_only.inputs[0].input_index = 1;
    second_only.signatures = after_first.signatures.clone();
    let after_second = sign_signing_envelope(&second_only, &parity_wif()).unwrap();
    assert_eq!(after_second.signatures.len(), 2);
    assert!(after_second.signatures.contains(&after_first.signatures[0]));

    // Signatures may reference inputs the envelope does not describe, but
    // never inputs the transaction does not have.
    let mut out_of_range = after_second.clone();
    out_of_range.signatures[0].input_index = 7;
    let error = sign_signing_envelope(&out_of_range, &parity_wif()).unwrap_err();
    assert!(error.to_string().contains("out of range"), "{error}");
}

#[test]
fn compose_builder_signs_every_input_of_a_multi_utxo_transaction() {
    let mut request = compose_request_base(
        "6666666666666666666666666666666666666666666666666666666666666666",
        100_000_000,
    );
    let mut second = request.utxos[0].clone();
    second.txid = "7777777777777777777777777777777777777777777777777777777777777777".to_owned();
    request.utxos.push(second);
    // Larger than either UTXO alone, so both must be selected and signed.
    request.outputs[0].value_koinu = 150_000_000;
    let result = compose_and_sign_transaction(&request).unwrap();
    assert_eq!(result.selected_inputs.len(), 2);
    let signed_tx_hex = result.signed_tx_hex.expect("both inputs are signed by the WIF");
    let tx: bitcoin::Transaction = deserialize(&hex::decode(&signed_tx_hex).unwrap()).unwrap();
    assert_eq!(tx.input.len(), 2);
    assert!(tx.input.iter().all(|input| !input.script_sig.is_empty()));
}
```

**Verify**: `cargo test -p easydoge-km --test parity` → compiles; the new tests fail (no validation yet) except `sign_p2pkh_transaction_still_signs_one_input_of_a_multi_input_transaction` and `compose_builder_signs_every_input_of_a_multi_utxo_transaction`, which pass before and after (the second one guards the builder path described in the Step 1 notes; if it fails at any point, the validator has broken the builder). Existing unrelated tests still pass.

### Step 3: Enforce in `sign_signing_envelope`

Replace the body of `sign_signing_envelope` with:

```rust
pub fn sign_signing_envelope(envelope: &SigningEnvelope, wif: &str) -> Result<SigningEnvelope> {
    let tx = parse_transaction(&envelope.unsigned_tx_hex)?;
    let validated = validate_envelope(envelope, &tx, DescriptorCoverage::Partial)?;
    let secret_key = secret_key_from_wif(wif, envelope.network)?;
    let secp = Secp256k1::new();
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    let public_key_hex = hex::encode(public_key.serialize());
    let cache = SighashCache::new(&tx);
    let mut signatures = envelope.signatures.clone();
    let mut controls_any_input = false;

    for input in &validated {
        if !input.controls(&public_key) {
            continue;
        }
        controls_any_input = true;
        let index = input.index();
        let already_signed = signatures.iter().any(|signature| {
            signature.input_index == index
                && signature.public_key_hex.eq_ignore_ascii_case(&public_key_hex)
        });
        if already_signed {
            continue;
        }
        let sighash = cache
            .legacy_signature_hash(
                index,
                input.signing_script.as_script(),
                input.descriptor.sighash_type,
            )
            .map_err(|err| Error::Crypto(err.to_string()))?;
        let message = Message::from_digest(sighash.to_byte_array());
        let mut der = secp.sign_ecdsa(&message, &secret_key).serialize_der().to_vec();
        der.push(input.sighash_flag);
        signatures.push(SigningEnvelopeSignature {
            input_index: index,
            public_key_hex: public_key_hex.clone(),
            signature_hex: hex::encode(der),
        });
    }

    if !controls_any_input {
        return Err(Error::InvalidKey(
            "WIF does not control any input in the signing envelope".to_owned(),
        ));
    }
    let mut next = envelope.clone();
    next.signatures = signatures;
    Ok(next)
}
```

**Verify**: `cargo test -p easydoge-km --test parity signing_envelope` → all `signing_envelope_*` tests pass, plus `sign_p2pkh_transaction_rejects_script_pubkey_not_owned_by_wif`. Then `cargo test -p easydoge-km --test parity compose_builder` → all builder tests still pass, including `compose_builder_signs_every_input_of_a_multi_utxo_transaction` (the builder signs partial envelopes that carry signatures for other inputs, which `DescriptorCoverage::Partial` allows). If any builder test fails here, see STOP conditions.

### Step 4: Enforce in `combine_signing_envelopes`

After the `first` lookup and before the loop, add:

```rust
    let tx = parse_transaction(&first.unsigned_tx_hex)?;
    validate_envelope(first, &tx, DescriptorCoverage::Partial)?;
```

and inside the loop, right after the metadata-equality check, add `validate_envelope(envelope, &tx, DescriptorCoverage::Partial)?;`.

**Verify**: `cargo test -p easydoge-km --test parity combine` → both combine tests pass.

### Step 5: Split finalization into a coverage-aware helper

Replace `finalize_signing_envelope` with a thin public wrapper plus a private `apply_signatures`, and make `sign_p2pkh_transaction` use the partial variant so it keeps signing one input of a multi-input transaction:

```rust
pub fn finalize_signing_envelope(envelope: &SigningEnvelope) -> Result<SignedTransaction> {
    apply_signatures(envelope, DescriptorCoverage::Complete)
}

fn apply_signatures(
    envelope: &SigningEnvelope,
    coverage: DescriptorCoverage,
) -> Result<SignedTransaction> {
    let mut tx = parse_transaction(&envelope.unsigned_tx_hex)?;
    let validated = validate_envelope(envelope, &tx, coverage)?;
    let mut script_sigs = Vec::with_capacity(validated.len());
    for input in &validated {
        let index = input.index();
        let mut matching: Vec<&SigningEnvelopeSignature> = envelope
            .signatures
            .iter()
            .filter(|signature| signature.input_index == index)
            .collect();
        matching.sort_by_key(|signature| signature.public_key_hex.as_str());
        if matching.is_empty() {
            return Err(Error::InvalidTransaction(format!(
                "input {index} has no signatures"
            )));
        }
        let script_sig = match input.descriptor.kind {
            SigningInputKind::P2pkh => {
                // Every signature was verified against the owning key in validate_envelope.
                /* existing P2PKH builder code, using matching[0] */
            }
            SigningInputKind::P2shMultisig => {
                let metadata = input
                    .multisig
                    .as_ref()
                    .expect("validated P2SH input carries multisig metadata");
                let redeem_script = input
                    .descriptor
                    .redeem_script_hex
                    .as_deref()
                    .expect("validated P2SH input carries a redeem script");
                /* existing filter / sort-by-redeem-script-order / dedup / threshold / builder code,
                   reading `metadata` and `redeem_script` instead of re-parsing */
            }
        };
        script_sigs.push((index, script_sig));
    }
    for (index, script_sig) in script_sigs {
        tx.input[index].script_sig = script_sig;
    }
    Ok(SignedTransaction {
        network: envelope.network,
        signed_tx_hex: hex::encode(serialize(&tx)),
    })
}
```

In `sign_p2pkh_transaction` (line 82) replace `finalize_signing_envelope(&envelope)` with `apply_signatures(&envelope, DescriptorCoverage::Partial)`. Remove the plan-001 `validated_sighash_flag` call from the old finalize loop (the validator already ran it) and the now-unused `input.input_index` range check (`tx.input.get_mut(...)`) since indices are validated.

**Verify**: `cargo test -p easydoge-km --locked` → all pass, including every test from Step 2.

### Step 6: Documentation

- `docs/API.md`: add a subsection `## Signing Envelopes` after the builder section: "A Signing Envelope describes the inputs a signer knows about; each input index may appear once and must exist in the unsigned transaction. P2PKH inputs carry a pay-to-pubkey-hash script pubkey; P2SH multisig inputs carry a redeem script whose hash matches the script pubkey. `sign_signing_envelope` signs only inputs the supplied WIF controls and errors when it controls none. `combine_signing_envelopes` and `finalize_signing_envelope` verify every signature (DER encoding, sighash flag, key ownership, and ECDSA validity against the legacy sighash) before accepting it, and finalization requires every transaction input to be described. A partial envelope may carry signatures for inputs it does not describe; those are verified when the envelope is finalized."
- `docs/SECURITY_MODEL.md`, "Core Guarantees": add "Signing envelopes are authenticated: input descriptors must match the unsigned transaction and each other, and every signature is verified before it is combined or finalized."
- `CHANGELOG.md` `### Security` (created by plan 001): add "Signing envelopes are now validated end to end: input descriptors must be unique and in range, P2SH redeem scripts must hash to their script pubkey, signing only covers inputs the key controls, combine/finalize verify every signature, and finalize requires every input to be described. Envelopes with forged or foreign signatures are rejected instead of producing invalid transactions."

**Verify**: `bash scripts/check-open-source-ready.sh` → exit 0.

### Step 7: Full verification including native wrappers

**Verify**: `./scripts/verify.sh` → exit 0. The Swift and Kotlin wrapper tests sign the parity P2PKH vector whose script pubkey belongs to the parity WIF, so they must pass unchanged.

## Test plan

- Rewritten: `p2sh_multisig_finalize_requires_threshold_signatures`, `p2sh_multisig_finalize_uses_redeem_script_public_key_order` (real keys, real signatures).
- New (all in `crates/easydoge-km/tests/parity.rs`): `signing_envelope_rejects_wif_that_controls_no_input`, `sign_p2pkh_transaction_rejects_script_pubkey_not_owned_by_wif`, `sign_p2pkh_transaction_still_signs_one_input_of_a_multi_input_transaction`, `signing_envelope_signs_only_inputs_owned_by_each_wif`, `signing_envelope_does_not_duplicate_signatures_from_the_same_key`, `signing_envelope_rejects_duplicate_and_out_of_range_input_descriptors`, `finalize_rejects_tampered_signature_bytes`, `finalize_rejects_signature_with_mismatched_sighash_flag`, `finalize_rejects_signature_from_key_that_does_not_control_input`, `finalize_rejects_envelope_that_does_not_describe_every_input`, `finalize_rejects_p2sh_script_pubkey_that_does_not_match_redeem_script`, `p2sh_multisig_cosigners_sign_separately_then_combine_and_finalize`, `combine_rejects_envelope_carrying_forged_signature`, `signing_envelope_keeps_signatures_for_inputs_it_does_not_describe`, `compose_builder_signs_every_input_of_a_multi_utxo_transaction`.
- Regression guard: `fixture_account_inspection_wif_message_and_transaction_are_deterministic` must still produce the exact `transaction.signed_tx_hex` from `test-vectors/parity.json`; `bash scripts/cross-check.sh` must still match bitcoinjs; plan 001's `sign_p2pkh_rejects_sighash_single_without_matching_output` (which signs input 1 of a two-input transaction through a one-input envelope) must still pass.

## Done criteria

Machine-checkable. ALL must hold:

- [ ] `cargo fmt --all --check` exits 0
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` exits 0
- [ ] `cargo test --workspace --locked` exits 0 and lists all 15 new test names plus the 2 rewritten ones
- [ ] `grep -n '"aa"\|"bb"\|signature_hex: "01"' crates/easydoge-km/tests/parity.rs` returns no matches (no fake signatures remain)
- [ ] `grep -n "fn validate_envelope" crates/easydoge-km/src/signing.rs` → 1 match, and `grep -c "validate_envelope(" crates/easydoge-km/src/signing.rs` ≥ 4 (call sites: sign + combine ×2 + apply_signatures; the generic definition line does not match this pattern)
- [ ] `grep -c "DescriptorCoverage::Complete" crates/easydoge-km/src/signing.rs` → exactly 2 (enum comparison in the validator + `finalize_signing_envelope`)
- [ ] `bash scripts/cross-check.sh` exits 0
- [ ] `./scripts/verify.sh` exits 0
- [ ] `git status --porcelain` lists only in-scope files
- [ ] `plans/README.md` status row updated

## STOP conditions

Stop and report back (do not improvise) if:

- Plan 001 is not marked DONE, or `validated_sighash_flag` does not exist in `signing.rs`.
- The "Current state" excerpts do not match the live code.
- Any `compose_builder_*` test fails after Step 3 or Step 5. The builder is out of scope; a failure there means the validator is stricter than the builder's own envelopes and the design needs a decision.
- The parity vector `transaction.signed_tx_hex` stops matching — this plan must not change signatures for valid inputs.
- `PublicKey::from_slice`, `Signature::from_der`, or `verify_ecdsa` are not available under the enabled `bitcoin`/`secp256k1` features (check `Cargo.lock`; `bitcoin-dogecoin 0.32.7-doge.0` with `rand-std` is expected).
- You need to change any file outside the scope list.

## Maintenance notes

- `validate_envelope` is now the single trust boundary for envelopes. Any new input kind (for example P2SH-wrapped single-key scripts) must be added there, with an ownership rule and a signing-script rule, before it is added to `SigningInputKind`.
- `sign_p2pkh_transaction` deliberately keeps producing a partially signed transaction when the unsigned transaction has more inputs than the one described; it is a single-input convenience API. Document-level callers who want "all inputs signed or error" should use envelopes and `finalize_signing_envelope`.
- `transaction_builder::envelope_is_complete` still relies on `multisig_threshold` / `multisig_public_keys_hex` metadata; a follow-up could derive completion from the validated redeem script instead (finding 13 is related).
- Verification is O(signatures) ECDSA operations per call; envelopes from untrusted parties should be size-capped (finding 17) before this is exposed to arbitrary input sizes.
- Reviewer focus: the P2PKH ownership check uses `hash160(compressed pubkey)`; uncompressed keys (finding 11) are intentionally still unsupported and will be reported as "does not control the input".
- The `Partial` coverage pass-through for signatures on undescribed inputs exists for the builder's one-input-at-a-time signing loop in `transaction_builder.rs`. If the builder is ever changed to sign with full-input envelopes, the pass-through can be removed so `sign` and `combine` reject undescribed signature indices. `compose_builder_signs_every_input_of_a_multi_utxo_transaction` fails if that coupling is broken.
- `verify_ecdsa` (libsecp256k1) accepts only low-S signatures. A co-signer that produces a high-S signature is rejected with "does not verify". This matches Dogecoin Core's LOW_S standardness policy, so such a transaction would have been refused by node mempools anyway. If lax acceptance is ever wanted, call `Signature::normalize_s` before verification and write the normalized signature into the scriptSig; never skip verification.
- Executed 2026-09-06: commit `6a55829`, reviewed and approved, PR https://github.com/simonbetton/easydoge-km/pull/41. The commit message says 13 new tests; the actual count is 15 (the two guard tests from the amendment are included in the diff).
