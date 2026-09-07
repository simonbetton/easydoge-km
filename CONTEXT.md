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

## Address Kind

The legacy Dogecoin script family identified from an address prefix, currently P2PKH or P2SH.

## Pasted Material

User-provided wallet or address text inspected by the TUI, such as an Address, Seed Phrase, Extended Private Key, Extended Public Key, or WIF.

## Inspector Result

The classified, redacted view of Pasted Material plus any metadata or derived addresses the SDK can safely show.

## Key Source

The seed phrase or extended key the TUI currently derives addresses from: the sample mnemonic, a generated mnemonic, or Pasted Material.

## Address Explorer

The TUI table of receive and change addresses derived from the Key Source for one account, with a cursor whose derivation path and public key are shown in full.

## Watch-only Derivation

Address derivation from public extended key material without access to private keys.

## Signing Envelope

A portable representation of an unsigned transaction, input metadata, redeem scripts, and collected signatures.

## Compose-and-Sign Transaction Builder

An offline transaction workflow that turns known spendable outputs, intended outputs, fee policy, and signer material into an unsigned transaction, a completed signed transaction, or a portable signing envelope.

## UTXO

An unspent transaction output that can be selected as an input to a future transaction.

## Koinu

The smallest Dogecoin amount unit.

## Script Pubkey

The locking script on an output that defines the conditions required to spend it.

## Redeem Script

The script revealed when spending a P2SH output.

## P2PKH

A pay-to-public-key-hash output spendable by a signature from the matching private key.

## P2SH Multisig

A pay-to-script-hash output whose redeem script requires signatures from a threshold of expected public keys.

## OP_RETURN

A zero-value data output that is provably unspendable.

## Dust

An output amount below the policy threshold for creating a spendable transaction output.

## Coin Selection

The choice of which UTXOs fund a transaction.

## Stored Wallet Handle

An opaque reference to wallet secret material managed by a platform storage adapter.

