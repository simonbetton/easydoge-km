# Security Policy

EasyDoge KM handles wallet key material. Please do not report suspected vulnerabilities in public issues.

## Reporting

GitHub private vulnerability reporting was disabled for this repository when checked on 2026-09-22. This repository does not currently document an alternative private reporting address.

If the [private reporting form](https://github.com/simonbetton/easydoge-km/security/advisories/new) becomes available, use it. Otherwise, ask the maintainer to arrange a private channel through an existing private contact or a public issue containing only that request. Do not include vulnerability details or wallet secrets in the public request.

Once a private channel is established, include:

- A short description of the issue.
- Affected package or platform surface.
- Reproduction steps or proof of concept.
- Whether any seed phrase, private key, WIF, xpriv, or transaction signature was exposed.

Do not include real user wallet secrets. Use disposable test vectors only.

## Scope

In scope:

- Key derivation mistakes.
- Address, WIF, xpriv, or xpub encoding mistakes.
- Signing flaws.
- Secret leakage through logs, CLI output, generated bindings, storage adapters, or errors.
- Supply-chain risks in release artifacts.

Out of scope:

- Dogecoin network consensus issues outside this SDK.
- Issues requiring compromised maintainer machines.
- Vulnerabilities in example applications not maintained in this repository.

## Supported Versions

No GitHub releases or tags were listed when checked on 2026-09-22. Package manifests currently declare `0.1.0`; that alone does not identify a published or supported release. The intended policy for future `0.x` releases is to apply security fixes to the latest release.

## Disclosure

Maintainers will acknowledge reports through the agreed private channel as soon as practical, prioritize fixes based on impact, and coordinate publication once patched releases are available.
