use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;

#[test]
fn mnemonic_generation_redacts_by_default() {
    let mut command = Command::cargo_bin("easydoge-km").unwrap();
    command
        .args(["--json", "mnemonic", "generate", "--words", "12"])
        .assert()
        .success()
        .stdout(predicate::str::contains("[redacted]"));
}

#[test]
fn mnemonic_validation_reports_true() {
    let phrase =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let mut command = Command::cargo_bin("easydoge-km").unwrap();
    command
        .args(["mnemonic", "validate", "--phrase", phrase])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"valid\": true"));
}

#[test]
fn address_validation_accepts_derived_mainnet_address() {
    let mut command = Command::cargo_bin("easydoge-km").unwrap();
    command
        .args([
            "address",
            "validate",
            "--address",
            "DMn7J63QSZUR9XNxsUJtvsttZVzV9Am4qM",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"valid\": true"));
}

#[test]
fn wif_export_redacts_by_default() {
    let xpriv = "dgpv58Apt2teSHcczCshu4Y4komJfUqVK8V6a336g1WPWeEKa4DTqeXY7qg1GqdvRU1kSSufZXP148tqq5b7q7PZYgvtwsp2YhxGqxkNgmBSVmB";
    let mut command = Command::cargo_bin("easydoge-km").unwrap();
    command
        .args(["--json", "wif", "export", "--xpriv", xpriv])
        .assert()
        .success()
        .stdout(predicate::str::contains("[redacted]"));
}

#[test]
fn tx_compose_prints_audited_result_without_echoing_wif() {
    let wif = "QS8wWhz1J58Ap7byfcEfGZHsWuTJAsB83XmAZLztEdCzYwbpCkT1";
    let request = serde_json::json!({
        "network": "mainnet",
        "utxos": [{
            "txid": "5555555555555555555555555555555555555555555555555555555555555555",
            "vout": 0,
            "previous_output_value_koinu": 100000000u64,
            "script_pubkey_hex": "76a9146dcc18cfcc4715927568546321b78541c8a83e7388ac",
            "kind": "p2pkh",
            "redeem_script_hex": null,
            "multisig_threshold": null,
            "multisig_public_keys_hex": [],
            "signers": [{
                "kind": "wif",
                "wif": wif,
                "xpriv": null,
                "derivation_path": null
            }],
            "manually_selected": false
        }],
        "outputs": [{
            "kind": "address",
            "value_koinu": 50000000u64,
            "address": "DMn7J63QSZUR9XNxsUJtvsttZVzV9Am4qM",
            "op_return_data_hex": null,
            "script_hex": null
        }],
        "fee_policy": {
            "fee_rate_koinu_per_kb": 1000u64,
            "dust_threshold_koinu": 1u64
        },
        "coin_selection": "min-inputs",
        "change": {
            "address": "DMn7J63QSZUR9XNxsUJtvsttZVzV9Am4qM",
            "xpriv": null,
            "derivation_path": null
        },
        "options": {
            "version": 1,
            "lock_time": 0,
            "sequence": 4294967295u32,
            "sighash_type": 1
        }
    });
    let path =
        std::env::temp_dir().join(format!("easydoge-km-compose-{}.json", std::process::id()));
    fs::write(&path, serde_json::to_string(&request).unwrap()).unwrap();

    let mut command = Command::cargo_bin("easydoge-km").unwrap();
    command
        .args([
            "--json",
            "tx",
            "compose",
            "--request-file",
            path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"signed_tx_hex\""))
        .stdout(predicate::str::contains(wif).not());

    let _ = fs::remove_file(path);
}

const PARITY_PHRASE: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const PARITY_ACCOUNT_XPRIV: &str = "dgpv58Apt2teSHcczCshu4Y4komJfUqVK8V6a336g1WPWeEKa4DTqeXY7qg1GqdvRU1kSSufZXP148tqq5b7q7PZYgvtwsp2YhxGqxkNgmBSVmB";
const PARITY_ACCOUNT_XPUB: &str = "dgub8s3rDipXzSGxH4XrwJA2sfJu83D89FWordpJq7uNJmHL87LAFR5Jm95er4g4Wa64yvNNY193By1pFiGMixHYZvyZiftVabMqWK7r1m4TSFC";
const PARITY_ACCOUNT_WIF: &str = "QS8wWhz1J58Ap7byfcEfGZHsWuTJAsB83XmAZLztEdCzYwbpCkT1";
const PARITY_ACCOUNT_ADDRESS: &str = "DF9eh53onfjPVUHabRXPaFcrZqbDBLNgW8";
const PARITY_RECEIVE_ADDRESS: &str = "DMn7J63QSZUR9XNxsUJtvsttZVzV9Am4qM";
const PARITY_UNSIGNED_TX_HEX: &str = "0100000001000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0000000000ffffffff0100e1f505000000001976a914b68208afee956eedc5cfac4b1998ac0afa6f2ddd88ac00000000";
const PARITY_SCRIPT_PUBKEY_HEX: &str = "76a9146dcc18cfcc4715927568546321b78541c8a83e7388ac";
const PARITY_SIGNED_TX_HEX: &str = "0100000001000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f000000006a473044022006e7d3cd624f468c4be67948d06a16e04ba2718c83b224bc96eccee998f99fda02206077fef79c7c84db56e8027a7d2a01cff30b28d6786775e0408e6ee0555765f80121027740a1dfcdd110e02e4c545dbc7b46a96ce39f866d0186507bb6fae8c5e0ebeeffffffff0100e1f505000000001976a914b68208afee956eedc5cfac4b1998ac0afa6f2ddd88ac00000000";
const PARITY_MESSAGE: &str = "EasyDoge KM parity";
const PARITY_MESSAGE_SIGNATURE: &str =
    "IISdVqfRyPxglPKa91Xj8b7lGTXHFnTJXOY2Evpu6/XqY9M1HkbJ5p2qVH4SwVzRpA9Ss5Eg5Q1AzaByuSwsv3g=";
const LITERAL_SECRET_WARNING: &str =
    "on the command line is visible in shell history and process listings";

/// A uniquely named temporary file that is removed when the test ends.
struct TempSecretFile {
    path: std::path::PathBuf,
}

impl TempSecretFile {
    /// `label` must be unique across this test file: tests run in parallel
    /// inside one process, so the process id alone does not separate them.
    fn new(label: &str, contents: impl AsRef<[u8]>) -> Self {
        let path =
            std::env::temp_dir().join(format!("easydoge-km-{label}-{}.txt", std::process::id()));
        fs::write(&path, contents).unwrap();
        Self { path }
    }

    fn path(&self) -> &str {
        self.path.to_str().unwrap()
    }
}

impl Drop for TempSecretFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn easydoge_km() -> Command {
    Command::cargo_bin("easydoge-km").unwrap()
}

#[test]
fn mnemonic_validation_reads_phrase_from_file_without_warning() {
    let phrase_file = TempSecretFile::new("validate-phrase-file", PARITY_PHRASE);
    easydoge_km()
        .args(["mnemonic", "validate", "--phrase-file", phrase_file.path()])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"valid\": true"))
        .stderr(predicate::str::is_empty());
}

#[test]
fn mnemonic_validation_reads_phrase_from_standard_input() {
    easydoge_km()
        .args(["mnemonic", "validate", "--phrase-file", "-"])
        .write_stdin(format!("{PARITY_PHRASE}\n"))
        .assert()
        .success()
        .stdout(predicate::str::contains("\"valid\": true"))
        .stderr(predicate::str::is_empty());
}

#[test]
fn literal_secret_flag_warns_on_stderr_without_echoing_the_secret() {
    easydoge_km()
        .args(["mnemonic", "validate", "--phrase", PARITY_PHRASE])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"valid\": true"))
        .stdout(predicate::str::contains("warning").not())
        .stderr(predicate::str::contains("warning: --phrase"))
        .stderr(predicate::str::contains(LITERAL_SECRET_WARNING))
        .stderr(predicate::str::contains("--phrase-file"))
        .stderr(predicate::str::contains("abandon").not());
}

#[test]
fn literal_passphrase_flag_warns_on_stderr() {
    let phrase_file = TempSecretFile::new("literal-passphrase-phrase", PARITY_PHRASE);
    easydoge_km()
        .args([
            "mnemonic",
            "to-seed",
            "--phrase-file",
            phrase_file.path(),
            "--passphrase",
            "TREZOR",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("warning: --passphrase"))
        .stderr(predicate::str::contains("warning: --phrase ").not())
        .stderr(predicate::str::contains("TREZOR").not());
}

#[test]
fn wif_file_has_exactly_one_trailing_line_ending_stripped() {
    for (label, line_ending) in [("lf", "\n"), ("crlf", "\r\n"), ("none", "")] {
        let wif_file = TempSecretFile::new(
            &format!("wif-line-ending-{label}"),
            format!("{PARITY_ACCOUNT_WIF}{line_ending}"),
        );
        easydoge_km()
            .args(["wif", "import", "--wif-file", wif_file.path()])
            .assert()
            .success()
            .stdout(predicate::str::contains(PARITY_ACCOUNT_ADDRESS))
            .stderr(predicate::str::is_empty());
    }
}

#[test]
fn account_xpriv_derives_from_phrase_file_and_passphrase_on_standard_input() {
    let phrase_file = TempSecretFile::new("from-mnemonic-phrase", format!("{PARITY_PHRASE}\r\n"));
    easydoge_km()
        .args([
            "--reveal",
            "xpriv",
            "from-mnemonic",
            "--phrase-file",
            phrase_file.path(),
            "--passphrase-file",
            "-",
        ])
        .write_stdin("TREZOR\n")
        .assert()
        .success()
        .stdout(predicate::str::contains(PARITY_ACCOUNT_XPRIV))
        .stderr(predicate::str::is_empty());
}

#[test]
fn passphrase_file_preserves_surrounding_spaces() {
    let phrase_file = TempSecretFile::new("spaces-phrase", PARITY_PHRASE);
    let passphrase_file = TempSecretFile::new("spaces-passphrase", " TREZOR \n");

    let from_file = easydoge_km()
        .args([
            "--reveal",
            "xpriv",
            "from-mnemonic",
            "--phrase-file",
            phrase_file.path(),
            "--passphrase-file",
            passphrase_file.path(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(PARITY_ACCOUNT_XPRIV).not())
        .get_output()
        .stdout
        .clone();

    let from_literal = easydoge_km()
        .args([
            "--reveal",
            "xpriv",
            "from-mnemonic",
            "--phrase-file",
            phrase_file.path(),
            "--passphrase",
            " TREZOR ",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    assert_eq!(from_file, from_literal);
}

#[test]
fn literal_and_file_secret_sources_conflict() {
    easydoge_km()
        .args([
            "mnemonic",
            "validate",
            "--phrase",
            PARITY_PHRASE,
            "--phrase-file",
            "unused.txt",
        ])
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("cannot be used with"))
        .stderr(predicate::str::contains("abandon").not());

    easydoge_km()
        .args([
            "mnemonic",
            "to-seed",
            "--phrase-file",
            "unused.txt",
            "--passphrase",
            "TREZOR",
            "--passphrase-file",
            "unused.txt",
        ])
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("cannot be used with"))
        .stderr(predicate::str::contains("TREZOR").not());
}

#[test]
fn missing_secret_source_is_rejected() {
    easydoge_km()
        .args(["mnemonic", "validate"])
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("--phrase-file <PATH>"));

    easydoge_km()
        .args(["address", "derive", "--path", "m/0/0"])
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("--xpriv-file <PATH>"));
}

#[test]
fn address_derive_rejects_xpub_combined_with_xpriv_file() {
    easydoge_km()
        .args([
            "address",
            "derive",
            "--xpub",
            PARITY_ACCOUNT_XPUB,
            "--xpriv-file",
            "unused.txt",
            "--path",
            "m/0/0",
        ])
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("cannot be used with"));
}

#[test]
fn only_one_secret_may_be_read_from_standard_input() {
    easydoge_km()
        .args([
            "mnemonic",
            "to-seed",
            "--phrase-file",
            "-",
            "--passphrase-file",
            "-",
        ])
        .write_stdin(format!("{PARITY_PHRASE}\n"))
        .assert()
        .failure()
        .code(1)
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains(
            "only one secret may be read from standard input",
        ))
        .stderr(predicate::str::contains("abandon").not());
}

#[test]
fn secret_file_errors_name_the_flag_and_path_but_never_the_contents() {
    let missing = std::env::temp_dir().join(format!(
        "easydoge-km-missing-secret-{}.txt",
        std::process::id()
    ));
    easydoge_km()
        .args(["wif", "import", "--wif-file", missing.to_str().unwrap()])
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("cannot read --wif-file"))
        .stderr(predicate::str::contains(missing.to_str().unwrap()));

    let empty = TempSecretFile::new("empty-secret", "\n");
    easydoge_km()
        .args(["wif", "import", "--wif-file", empty.path()])
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("--wif-file"))
        .stderr(predicate::str::contains("is empty"));

    let oversized = TempSecretFile::new("oversized-secret", "k".repeat(64 * 1024 + 1));
    easydoge_km()
        .args(["wif", "import", "--wif-file", oversized.path()])
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("larger than 65536 bytes"))
        .stderr(predicate::str::contains("kkkk").not());

    let not_text = TempSecretFile::new("binary-secret", [0xff_u8, 0xfe, 0xfd]);
    easydoge_km()
        .args(["wif", "import", "--wif-file", not_text.path()])
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("is not valid UTF-8"));

    let malformed = TempSecretFile::new("malformed-secret", "not-a-wif-SENTINEL-value\n");
    easydoge_km()
        .args(["wif", "import", "--wif-file", malformed.path()])
        .assert()
        .failure()
        .code(1)
        .stdout(predicate::str::contains("SENTINEL").not())
        .stderr(predicate::str::contains("SENTINEL").not());
}

#[test]
fn every_secret_bearing_subcommand_accepts_the_file_form() {
    let phrase = TempSecretFile::new("all-phrase", format!("{PARITY_PHRASE}\n"));
    let passphrase = TempSecretFile::new("all-passphrase", "TREZOR\n");
    let xpriv = TempSecretFile::new("all-xpriv", format!("{PARITY_ACCOUNT_XPRIV}\n"));
    let wif = TempSecretFile::new("all-wif", format!("{PARITY_ACCOUNT_WIF}\n"));
    let envelope = TempSecretFile::new(
        "all-envelope",
        serde_json::json!({
            "version": 1,
            "network": "mainnet",
            "unsigned_tx_hex": PARITY_UNSIGNED_TX_HEX,
            "inputs": [{
                "input_index": 0,
                "kind": "p2pkh",
                "script_pubkey_hex": PARITY_SCRIPT_PUBKEY_HEX,
                "redeem_script_hex": null,
                "sighash_type": 1
            }],
            "signatures": []
        })
        .to_string(),
    );

    // `{name}` words are replaced after splitting on spaces, so substituted
    // values may themselves contain spaces.
    let cases = [
        ("mnemonic validate --phrase-file {phrase}", "\"valid\": true"),
        (
            "mnemonic to-seed --phrase-file {phrase} --passphrase-file {passphrase}",
            "[redacted]",
        ),
        (
            "--reveal xpriv from-mnemonic --phrase-file {phrase} --passphrase-file {passphrase}",
            PARITY_ACCOUNT_XPRIV,
        ),
        ("xpriv inspect --xpriv-file {xpriv}", "\"depth\": 3"),
        (
            "xpriv derive-address --xpriv-file {xpriv} --path m/0/0",
            PARITY_RECEIVE_ADDRESS,
        ),
        ("xpriv derive --xpriv-file {xpriv} --path m/0/0", "[redacted]"),
        ("xpriv to-xpub --xpriv-file {xpriv}", PARITY_ACCOUNT_XPUB),
        (
            "address derive --xpriv-file {xpriv} --path m/0/0",
            PARITY_RECEIVE_ADDRESS,
        ),
        ("wif export --xpriv-file {xpriv}", "[redacted]"),
        ("wif import --wif-file {wif}", PARITY_ACCOUNT_ADDRESS),
        (
            "multisig sign --envelope-file {envelope} --wif-file {wif}",
            "\"signature_hex\"",
        ),
        (
            "tx sign-p2pkh --unsigned-tx-hex {tx} --input-index 0 --script-pubkey-hex {script} --wif-file {wif}",
            PARITY_SIGNED_TX_HEX,
        ),
        (
            "--reveal message sign --wif-file {wif} --message {message}",
            PARITY_MESSAGE_SIGNATURE,
        ),
    ];

    for (template, expected_stdout) in cases {
        let args: Vec<&str> = template
            .split(' ')
            .map(|word| match word {
                "{phrase}" => phrase.path(),
                "{passphrase}" => passphrase.path(),
                "{xpriv}" => xpriv.path(),
                "{wif}" => wif.path(),
                "{envelope}" => envelope.path(),
                "{tx}" => PARITY_UNSIGNED_TX_HEX,
                "{script}" => PARITY_SCRIPT_PUBKEY_HEX,
                "{message}" => PARITY_MESSAGE,
                other => other,
            })
            .collect();
        easydoge_km()
            .args(&args)
            .assert()
            .success()
            .stdout(predicate::str::contains(expected_stdout))
            .stderr(predicate::str::is_empty());
    }
}
