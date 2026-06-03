use assert_cmd::Command;
use predicates::prelude::*;

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
