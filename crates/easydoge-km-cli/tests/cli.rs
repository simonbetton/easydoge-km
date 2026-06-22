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
