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
  wifFromXpriv(xpriv: Xpriv): Promise<string>;
  addressFromWif(network: Network, wif: string): Promise<WifInfo>;
  validateAddress(network: Network, address: string): Promise<boolean>;
  storeMnemonic(phrase: string, protection: StoredWalletProtection): Promise<StoredWalletHandle>;
  exportMnemonic(handle: StoredWalletHandle, protection: StoredWalletProtection): Promise<string>;
  protectionLevel(handle: StoredWalletHandle): Promise<StorageProtectionLevel>;
}

const EasyDogeKM = requireNativeModule<EasyDogeKMModule>("EasyDogeKM");
export default EasyDogeKM;

import { requireNativeModule } from "expo-modules-core";
