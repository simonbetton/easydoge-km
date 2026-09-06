# Plan 001: Reject undefined sighash types and the SIGHASH_SINGLE output-index bug

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md` — unless a reviewer dispatched you and told you they
> maintain the index.
>
> **Drift check (run first)**:
> `git diff --stat 32f1e4d..HEAD -- crates/easydoge-km/src/signing.rs crates/easydoge-km/src/transaction_builder.rs crates/easydoge-km/tests/parity.rs docs/API.md docs/SECURITY_MODEL.md CHANGELOG.md`
> If any in-scope file changed since this plan was written, compare the
> "Current state" excerpts against the live code before proceeding; on a
> mismatch, treat it as a STOP condition.

## Status

- **Priority**: P1
- **Effort**: S
- **Risk**: MED (behavior change: callers passing non-standard sighash values now get an error)
- **Depends on**: none
- **Category**: security
- **Planned at**: commit `32f1e4d`, 2026-09-04
- **Audit finding**: #5 (deep audit, evidence originally collected at `04e7499`, revalidated at `32f1e4d`)

## Why this matters

The core accepts any `u32` as a sighash type. The full 32-bit value is hashed
into the signature preimage, but only its low byte is appended to the DER
signature, so any value above `0xff` produces a signature that no verifier can
reproduce — the transaction is silently unspendable. Worse, `SIGHASH_SINGLE`
(`0x03`/`0x83`) on an input index with no matching output triggers the
consensus "SIGHASH_SINGLE bug": rust-bitcoin returns the constant hash `1`, and
a signature over that constant is valid for *any* transaction that reuses the
same key with the same shape — a real fund-loss hazard for a wallet SDK. After
this plan, only the six consensus-defined sighash values are accepted, and
`SIGHASH_SINGLE` is rejected when the input index has no output at that index.

## Current state

Files and roles:

- `crates/easydoge-km/src/signing.rs` — envelope signing/finalization. Hashes with the raw `u32` and pushes `as u8` (lines 92–111).
- `crates/easydoge-km/src/transaction_builder.rs` — compose-and-sign builder. `TransactionOptions.sighash_type: u32` (line 150) is never validated in `validate_request` (lines 330–352) and is copied into every envelope input (line 270).
- `crates/easydoge-km/tests/parity.rs` — the single integration test file for the core crate; add new tests here.
- `crates/easydoge-km-cli/src/main.rs` — `tx sign-p2pkh --sighash-type <u32>` (lines 240–241) passes the value straight through. No change needed there.
- `crates/easydoge-km-ffi/src/lib.rs` — `sighash_type: u32` in records (lines 130, 230). No change needed.

Excerpt, `crates/easydoge-km/src/signing.rs:92-111` (today):

```rust
    for input in &envelope.inputs {
        let script_hex = input
            .redeem_script_hex
            .as_deref()
            .unwrap_or(input.script_pubkey_hex.as_str());
        let script = parse_script(script_hex)?;
        let cache = SighashCache::new(&tx);
        let sighash = cache
            .legacy_signature_hash(input.input_index, script.as_script(), input.sighash_type)
            .map_err(|err| Error::Crypto(err.to_string()))?;
        let message = Message::from_digest(sighash.to_byte_array());
        let signature = secp.sign_ecdsa(&message, &secret_key);
        let mut der = signature.serialize_der().to_vec();
        der.push(input.sighash_type as u8);
        signatures.push(SigningEnvelopeSignature {
            input_index: input.input_index,
            public_key_hex: hex::encode(public_key.serialize()),
            signature_hex: hex::encode(der),
        });
    }
```

Excerpt, `crates/easydoge-km/src/transaction_builder.rs:330-352` (today):

```rust
fn validate_request(request: &ComposeTransactionRequest) -> Result<()> {
    if request.utxos.is_empty() { /* ... */ }
    if request.outputs.is_empty() { /* ... */ }
    if request.fee_policy.fee_rate_koinu_per_kb == 0 { /* ... */ }
    if request.options.version <= 0 {
        return Err(Error::InvalidTransaction(
            "transaction version must be positive".to_owned(),
        ));
    }
    Ok(())
}
```

How rust-bitcoin (`bitcoin-dogecoin 0.32.7-doge.0`, `src/crypto/sighash.rs`) behaves, verified in the cargo registry:

- `SighashCache::legacy_signature_hash(input_index, script, sighash_type: u32)` returns `LegacySighash::from_byte_array(UINT256_ONE)` when `EcdsaSighashType::from_consensus(sighash_type).is_single() && input_index >= outputs_len`. That is the bug path this plan closes.
- `EcdsaSighashType::from_consensus` masks with `0x9f`, so `0x41`, `0x101`, `0xff01` etc. silently map to ALL while the full `u32` is still committed into the preimage at line 989 (`sighash_type.to_le_bytes().consensus_encode(writer)`).

Repo conventions to match:

- Errors are `crate::Error` variants with descriptive lowercase messages, e.g. `Error::InvalidTransaction("fee rate must be greater than zero".to_owned())`. Use `Error::InvalidTransaction` for everything in this plan.
- Tests live in `crates/easydoge-km/tests/parity.rs`, snake_case names that read as sentences (`compose_builder_rejects_signer_that_does_not_match_p2pkh_utxo`), and assert on `error.to_string().contains("...")`.
- `CONTRIBUTING.md` requires TDD: write the failing test first, then the smallest change. It also requires updating `docs/API.md`, `docs/SECURITY_MODEL.md`, and `CHANGELOG.md` when public behavior changes.
- `scripts/check-open-source-ready.sh` fails the whole verify run if the uppercase marker words for "to do" / "fix me" appear anywhere in the repo. Do not write them in code comments or docs.

Vocabulary from `CONTEXT.md` to use in names and comments: "Signing Envelope", "Compose-and-Sign Transaction Builder".

## Commands you will need

| Purpose | Command | Expected on success |
|---------|---------|---------------------|
| Format check | `cargo fmt --all --check` | exit 0 |
| Run one test | `cargo test -p easydoge-km --test parity <test_name>` | `test result: ok` |
| Core tests | `cargo test -p easydoge-km --locked` | all pass |
| Workspace tests | `cargo test --workspace --locked` | all pass (25 existing + new) |
| Clippy | `cargo clippy --workspace --all-targets -- -D warnings` | exit 0 |
| Cross-check | `bash scripts/cross-check.sh` | exit 0, prints that outputs match (needs Node 20 + pnpm) |
| Readiness | `bash scripts/check-open-source-ready.sh` | exit 0 |
| Full suite | `./scripts/verify.sh` | exit 0 |

## Suggested executor toolkit

- If the `tdd` skill is available, use it for Steps 2–4 (red → green per test).

## Scope

**In scope** (the only files you should modify):

- `crates/easydoge-km/src/signing.rs`
- `crates/easydoge-km/src/transaction_builder.rs`
- `crates/easydoge-km/tests/parity.rs`
- `docs/API.md`, `docs/SECURITY_MODEL.md`, `CHANGELOG.md`

**Out of scope** (do NOT touch, even though they look related):

- `crates/easydoge-km-ffi/src/lib.rs`, generated Swift/Kotlin bindings, Expo module — the wire type stays `u32`; validation happens in the core.
- `crates/easydoge-km-cli/src/main.rs` — the CLI flag stays `u32`; the core error propagates.
- Signature verification / ownership checks in envelopes — that is plan 002.
- `tools/bitcoinjs-cross-check/**` and `test-vectors/cross-check.json` — all cross-check cases use sighash `1`; nothing changes there.

## Git workflow

- Branch: `fix/sighash-type-validation` (repo uses `fix/…`, `feat/…`, `chore/…` prefixes).
- Conventional Commits, e.g. `fix(signing): reject undefined sighash types and SIGHASH_SINGLE bug` (compare `fix(tui): clear stale address source when pasting a seed phrase` in `git log`).
- Do NOT push or open a PR unless the operator instructed it.

## Steps

### Step 1: Add the validation helpers to `signing.rs`

Add near the top of `crates/easydoge-km/src/signing.rs` (after the `use` block):

```rust
const SIGHASH_ALL: u32 = 0x01;
const SIGHASH_NONE: u32 = 0x02;
const SIGHASH_SINGLE: u32 = 0x03;
const SIGHASH_ANYONECANPAY: u32 = 0x80;

/// Accepts only the six consensus-defined sighash values and returns the
/// single byte appended to a DER signature.
pub(crate) fn validate_sighash_type(sighash_type: u32) -> Result<u8> {
    let base = sighash_type & !SIGHASH_ANYONECANPAY;
    let recognised =
        sighash_type <= 0xff && matches!(base, SIGHASH_ALL | SIGHASH_NONE | SIGHASH_SINGLE);
    if !recognised {
        return Err(Error::InvalidTransaction(format!(
            "unsupported sighash type {sighash_type:#x}; expected 0x01, 0x02, 0x03, 0x81, 0x82, or 0x83"
        )));
    }
    Ok(sighash_type as u8)
}

/// Validates the sighash type for one input, including the SIGHASH_SINGLE
/// rule that the input index must have a matching output.
pub(crate) fn validated_sighash_flag(
    sighash_type: u32,
    input_index: usize,
    output_count: usize,
) -> Result<u8> {
    let flag = validate_sighash_type(sighash_type)?;
    if (sighash_type & !SIGHASH_ANYONECANPAY) == SIGHASH_SINGLE && input_index >= output_count {
        return Err(Error::InvalidTransaction(format!(
            "SIGHASH_SINGLE for input {input_index} requires an output at index {input_index}, but the transaction has {output_count} outputs"
        )));
    }
    Ok(flag)
}
```

Sanity table for `validate_sighash_type`: `0x01/0x02/0x03/0x81/0x82/0x83` → Ok; `0x00`, `0x04`, `0x41`, `0x80`, `0x101`, `0xff01` → Err.

**Verify**: `cargo build -p easydoge-km` → exit 0 (dead-code warnings are fine at this step).

### Step 2: Write the failing tests

Append to `crates/easydoge-km/tests/parity.rs`. Add `use bitcoin::consensus::encode::{deserialize, serialize};` to the imports (the `bitcoin` crate is already used by this file via `bitcoin::hashes`). Add `sign_p2pkh_transaction`-related helpers as shown.

```rust
fn parity_unsigned_tx_hex() -> String {
    vectors()["transaction"]["unsigned_tx_hex"]
        .as_str()
        .unwrap()
        .to_owned()
}

fn parity_script_pubkey_hex() -> String {
    vectors()["transaction"]["script_pubkey_hex"]
        .as_str()
        .unwrap()
        .to_owned()
}

fn parity_wif() -> String {
    vectors()["mnemonic"]["account"]["wif"]
        .as_str()
        .unwrap()
        .to_owned()
}

/// The parity transaction with its single input duplicated (vout 1), giving
/// two inputs and one output.
fn two_input_unsigned_tx_hex() -> String {
    let mut tx: bitcoin::Transaction =
        deserialize(&hex::decode(parity_unsigned_tx_hex()).unwrap()).unwrap();
    let mut second = tx.input[0].clone();
    second.previous_output.vout = 1;
    tx.input.push(second);
    hex::encode(serialize(&tx))
}

#[test]
fn sign_p2pkh_rejects_sighash_types_outside_consensus_set() {
    for sighash_type in [0x00u32, 0x04, 0x41, 0x80, 0x101, 0xff01] {
        let error = sign_p2pkh_transaction(
            Network::Mainnet,
            &parity_unsigned_tx_hex(),
            0,
            &parity_script_pubkey_hex(),
            &parity_wif(),
            sighash_type,
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("unsupported sighash type"),
            "{sighash_type:#x}: {error}"
        );
    }
}

#[test]
fn sign_p2pkh_accepts_anyone_can_pay_and_appends_flag_byte() {
    let signed = sign_p2pkh_transaction(
        Network::Mainnet,
        &parity_unsigned_tx_hex(),
        0,
        &parity_script_pubkey_hex(),
        &parity_wif(),
        0x81,
    )
    .unwrap();
    let tx: bitcoin::Transaction =
        deserialize(&hex::decode(&signed.signed_tx_hex).unwrap()).unwrap();
    let script_sig = tx.input[0].script_sig.as_bytes();
    let signature_push_len = usize::from(script_sig[0]);
    assert_eq!(script_sig[signature_push_len], 0x81);
}

#[test]
fn sign_p2pkh_rejects_sighash_single_without_matching_output() {
    let unsigned = two_input_unsigned_tx_hex();
    let error = sign_p2pkh_transaction(
        Network::Mainnet,
        &unsigned,
        1,
        &parity_script_pubkey_hex(),
        &parity_wif(),
        0x03,
    )
    .unwrap_err();
    assert!(error.to_string().contains("SIGHASH_SINGLE"), "{error}");

    // Input 0 does have a matching output, so SINGLE is allowed there.
    sign_p2pkh_transaction(
        Network::Mainnet,
        &unsigned,
        0,
        &parity_script_pubkey_hex(),
        &parity_wif(),
        0x03,
    )
    .unwrap();
}

#[test]
fn compose_builder_rejects_unsupported_sighash_type() {
    let mut request = compose_request_base(
        "5555555555555555555555555555555555555555555555555555555555555555",
        100_000_000,
    );
    request.options.sighash_type = 0x80;
    let error = compose_and_sign_transaction(&request).unwrap_err();
    assert!(error.to_string().contains("unsupported sighash type"), "{error}");
}

#[test]
fn finalize_rejects_envelope_input_with_unsupported_sighash_type() {
    let envelope = SigningEnvelope {
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
    };
    let mut signed = easydoge_km::sign_signing_envelope(&envelope, &parity_wif()).unwrap();
    signed.inputs[0].sighash_type = 0x104;
    let error = finalize_signing_envelope(&signed).unwrap_err();
    assert!(error.to_string().contains("unsupported sighash type"), "{error}");
}
```

Note on the `0x81` assertion: a P2PKH scriptSig is `[push_len][DER…][flag][0x21][33-byte pubkey]`, so the byte at index `push_len` is the flag.

**Verify**: `cargo test -p easydoge-km --test parity sighash` → the four `sighash`-named tests **fail** (compile succeeds; assertions fail because no validation exists yet). `compose_builder_rejects_unsupported_sighash_type` also fails.

### Step 3: Enforce in `sign_signing_envelope` and `finalize_signing_envelope`

In `sign_signing_envelope` (signing.rs, the loop shown in "Current state"), before computing the sighash:

```rust
        let sighash_flag =
            validated_sighash_flag(input.sighash_type, input.input_index, tx.output.len())?;
```

and replace `der.push(input.sighash_type as u8);` with `der.push(sighash_flag);`.

In `finalize_signing_envelope`, at the top of the `for input in &envelope.inputs` loop, add:

```rust
        validated_sighash_flag(input.sighash_type, input.input_index, tx.output.len())?;
```

(`tx` is already parsed on the first line of that function.)

**Verify**: `cargo test -p easydoge-km --test parity sighash` → all pass except `compose_builder_rejects_unsupported_sighash_type` (still failing, handled in Step 4).

### Step 4: Enforce in the Compose-and-Sign Transaction Builder

In `crates/easydoge-km/src/transaction_builder.rs`:

1. Extend the `use crate::signing::{...}` import with `validate_sighash_type, validated_sighash_flag`.
2. In `validate_request`, after the version check, add:

```rust
    validate_sighash_type(request.options.sighash_type)?;
```

3. In `compose_and_sign_transaction`, immediately after `let tx = build_unsigned_transaction(request, &selected_utxos, outputs)?;`, add:

```rust
    for input_index in 0..tx.input.len() {
        validated_sighash_flag(request.options.sighash_type, input_index, tx.output.len())?;
    }
```

This gives a clear error for SIGHASH_SINGLE requests whose selected-input count exceeds the output count, before any signing happens.

**Verify**: `cargo test -p easydoge-km --locked` → all pass, including the five new tests.

### Step 5: Documentation

- `docs/API.md`, section "Compose-and-Sign Transaction Builder", bullet `options:` — append: "Only the consensus-defined sighash types are accepted: `0x01` (ALL), `0x02` (NONE), `0x03` (SINGLE) and their `0x80` ANYONECANPAY variants. `SIGHASH_SINGLE` is rejected for any input index that has no output at the same index."
- `docs/SECURITY_MODEL.md`, list "Core Guarantees" — add bullet: "Signing rejects undefined sighash types and the SIGHASH_SINGLE output-index bug."
- `CHANGELOG.md`, under `## [Unreleased]`, add a `### Security` heading after `### Changed` with: "Transaction signing and the Compose-and-Sign Transaction Builder now reject sighash types other than the six consensus-defined values and reject `SIGHASH_SINGLE` for inputs without a matching output. Previously any `u32` was accepted, producing unspendable or, for the SIGHASH_SINGLE bug case, dangerously reusable signatures."

**Verify**: `bash scripts/check-open-source-ready.sh` → exit 0.

### Step 6: Full verification

**Verify**: `cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace --locked` → all exit 0. Then `bash scripts/cross-check.sh` → exit 0 (all cross-check cases use sighash 1, so output is unchanged).

## Test plan

New tests in `crates/easydoge-km/tests/parity.rs` (Step 2), modeled on `compose_builder_rejects_signer_that_does_not_match_p2pkh_utxo`:

- `sign_p2pkh_rejects_sighash_types_outside_consensus_set` — six rejected values.
- `sign_p2pkh_accepts_anyone_can_pay_and_appends_flag_byte` — `0x81` accepted, flag byte serialized.
- `sign_p2pkh_rejects_sighash_single_without_matching_output` — the SIGHASH_SINGLE bug path is closed; index 0 still works.
- `compose_builder_rejects_unsupported_sighash_type` — builder validates `options.sighash_type`.
- `finalize_rejects_envelope_input_with_unsupported_sighash_type` — finalize validates descriptors.

Existing tests must keep passing unchanged, in particular `fixture_account_inspection_wif_message_and_transaction_are_deterministic` (sighash 1, parity vector) and the Swift/Kotlin wrapper tests (also sighash 1).

## Done criteria

Machine-checkable. ALL must hold:

- [ ] `cargo fmt --all --check` exits 0
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` exits 0
- [ ] `cargo test --workspace --locked` exits 0 and reports the five new test names
- [ ] `grep -n "as u8" crates/easydoge-km/src/signing.rs` shows no `sighash_type as u8` outside `validate_sighash_type`
- [ ] `grep -c "unsupported sighash type" docs/API.md CHANGELOG.md` → both ≥ 1 (wording may differ; the concept must be documented)
- [ ] `bash scripts/check-open-source-ready.sh` exits 0
- [ ] `git status --porcelain` lists only in-scope files
- [ ] `plans/README.md` status row updated

## STOP conditions

Stop and report back (do not improvise) if:

- The excerpts in "Current state" do not match the live code (drift).
- `legacy_signature_hash` in the pinned `bitcoin-dogecoin` crate no longer takes a `u32` (signature change after a dependency bump).
- Any existing test starts failing for a reason other than a sighash value — this plan must not change output for sighash `1`.
- You find you need to change `crates/easydoge-km-ffi` or the CLI to make a test pass.

## Maintenance notes

- Plan 002 (envelope authentication) reuses `validated_sighash_flag` inside its envelope validator and additionally checks that each signature's trailing byte equals the input's flag. Keep the helper `pub(crate)`.
- If a future feature needs non-standard sighash values (there is no known Dogecoin use case), extend `validate_sighash_type` deliberately and add a test; never widen it to "any byte".
- Reviewer focus: the SIGHASH_SINGLE guard must use `tx.output.len()` of the *unsigned* transaction being signed, not the request's output list (the builder appends a change output).
