export type Network = "mainnet" | "testnet" | "regtest";
export type Language =
  | "english"
  | "simplified-chinese"
  | "traditional-chinese"
  | "czech"
  | "french"
  | "italian"
  | "japanese"
  | "korean"
  | "portuguese"
  | "spanish";

export interface MnemonicOptions {
  language?: Language;
  wordCount?: 12 | 15 | 18 | 21 | 24;
}

export interface GeneratedMnemonic {
  phrase: string;
  language: Language;
  wordCount: number;
}

export interface Xpriv {
  network: Network;
  encoded: string;
}

export interface Xpub {
  network: Network;
  encoded: string;
}

export interface AccountKeySet {
  network: Network;
  account: number;
  accountPath: string;
  xpriv: Xpriv;
  xpub: Xpub;
}

export interface PathAddress {
  network: Network;
  path: string;
  publicKeyHex: string;
  address: string;
}

export interface WifInfo {
  network: Network;
  publicKeyHex: string;
  address: string;
  compressed: boolean;
}

export interface ExtendedKeyInfo {
  network: Network;
  depth: number;
  parentFingerprintHex: string;
  childNumber: number;
  publicKeyHex?: string | null;
  privateKeyRedacted: boolean;
}

export interface MultisigDescriptor {
  network: Network;
  threshold: number;
  cosignerCount: number;
  childPath: string;
  sorted: boolean;
  publicKeysHex: string[];
  redeemScriptHex: string;
  p2shAddress: string;
}

export interface MessageSignature {
  network: Network;
  address: string;
  signatureBase64: string;
}

export interface SignedTransaction {
  network: Network;
  signedTxHex: string;
}

export type SigningInputKind = "p2pkh" | "p2sh-multisig";

export interface SigningEnvelopeInput {
  inputIndex: number;
  kind: SigningInputKind;
  scriptPubkeyHex: string;
  redeemScriptHex?: string | null;
  sighashType: number;
}

export interface SigningEnvelopeSignature {
  inputIndex: number;
  publicKeyHex: string;
  signatureHex: string;
}

export interface SigningEnvelope {
  version: number;
  network: Network;
  unsignedTxHex: string;
  inputs: SigningEnvelopeInput[];
  signatures: SigningEnvelopeSignature[];
}

export interface StoredWalletHandle {
  id: string;
}

export type StoredWalletProtection = "no-prompt" | "device-credential" | "biometric";
export type StorageProtectionLevel = "hardware-backed" | "os-backed" | "unsupported";

export interface EasyDogeKMModule {
  generateMnemonic(options?: MnemonicOptions): Promise<GeneratedMnemonic>;
  validateMnemonic(phrase: string, language?: Language): Promise<boolean>;
  mnemonicToSeedHex(phrase: string, passphrase?: string, language?: Language): Promise<string>;
  accountKeysFromMnemonic(
    phrase: string,
    passphrase: string | undefined,
    language: Language,
    network: Network,
    account: number,
  ): Promise<AccountKeySet>;
  derivePathFromXpriv(xpriv: Xpriv, path: string): Promise<Xpriv>;
  derivePathFromXpub(xpub: Xpub, path: string): Promise<Xpub>;
  xpubFromXpriv(xpriv: Xpriv): Promise<Xpub>;
  deriveAddressFromXpriv(xpriv: Xpriv, path: string): Promise<PathAddress>;
  deriveAddressFromXpub(xpub: Xpub, path: string): Promise<PathAddress>;
  inspectXpriv(xpriv: Xpriv): Promise<ExtendedKeyInfo>;
  inspectXpub(xpub: Xpub): Promise<ExtendedKeyInfo>;
  wifFromXpriv(xpriv: Xpriv): Promise<string>;
  addressFromWif(network: Network, wif: string): Promise<WifInfo>;
  validateAddress(network: Network, address: string): Promise<boolean>;
  createMultisigDescriptor(
    network: Network,
    threshold: number,
    cosignerXpubs: Xpub[],
    childPath: string,
    sorted: boolean,
  ): Promise<MultisigDescriptor>;
  signMessage(network: Network, wif: string, message: string): Promise<MessageSignature>;
  verifyMessage(
    network: Network,
    address: string,
    signatureBase64: string,
    message: string,
  ): Promise<boolean>;
  signP2pkhTransaction(
    network: Network,
    unsignedTxHex: string,
    inputIndex: number,
    scriptPubkeyHex: string,
    wif: string,
    sighashType: number,
  ): Promise<SignedTransaction>;
  signSigningEnvelope(envelope: SigningEnvelope, wif: string): Promise<SigningEnvelope>;
  combineSigningEnvelopes(envelopes: SigningEnvelope[]): Promise<SigningEnvelope>;
  finalizeSigningEnvelope(envelope: SigningEnvelope): Promise<SignedTransaction>;
  storeMnemonic(phrase: string, protection: StoredWalletProtection): Promise<StoredWalletHandle>;
  exportMnemonic(handle: StoredWalletHandle, protection: StoredWalletProtection): Promise<string>;
  protectionLevel(handle: StoredWalletHandle): Promise<StorageProtectionLevel>;
}

const EasyDogeKM = requireNativeModule<EasyDogeKMModule>("EasyDogeKM");
export default EasyDogeKM;

import { requireNativeModule } from "expo-modules-core";
