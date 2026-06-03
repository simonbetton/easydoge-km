# Context

## Seed Phrase

A human-readable BIP39 mnemonic used as the user's backup secret.

## BIP39 Seed

The binary seed derived from a Seed Phrase and optional passphrase.

## Extended Private Key

A BIP32 private extended key that can derive child private keys and corresponding public keys.

## Extended Public Key

A BIP32 public extended key that can derive non-hardened child public keys and watch-only addresses.

## Account

A hardened Dogecoin BIP44 branch used as the parent for receive and change address derivation.

## Address

A network-specific Dogecoin destination string derived from public key or script material.

## Watch-only Derivation

Address derivation from public extended key material without access to private keys.

## Signing Envelope

A portable representation of an unsigned transaction, input metadata, redeem scripts, and collected signatures.

## Stored Wallet Handle

An opaque reference to wallet secret material managed by a platform storage adapter.

