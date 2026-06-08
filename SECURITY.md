# Security Policy

EasyDoge KM handles wallet key material. Please do not report suspected vulnerabilities in public issues.

## Reporting

Report suspected vulnerabilities through GitHub private vulnerability reporting:

https://github.com/simonbetton/easydoge-km/security/advisories/new

Include:

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

During the `0.x` series, only the latest released version receives security fixes.

## Disclosure

Maintainers will acknowledge reports through the private advisory thread as soon as practical, prioritize fixes based on impact, and coordinate publication once patched releases are available.
