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

/**
 * Koinu amount as a canonical unsigned decimal string: "0" or digits with no
 * leading zero, at most 18446744073709551615. JavaScript numbers cannot
 * represent every u64 koinu value, so amounts cross the native bridge as
 * strings. Use koinuFromBigInt / koinuToBigInt for arithmetic.
 */
export type Koinu = string;

export const MAX_KOINU = 18446744073709551615n;

const CANONICAL_DECIMAL = /^(0|[1-9][0-9]*)$/;

export function isKoinu(value: unknown): value is Koinu {
  return (
    typeof value === "string" &&
    value.length <= 20 &&
    CANONICAL_DECIMAL.test(value) &&
    BigInt(value) <= MAX_KOINU
  );
}

export function koinuFromBigInt(value: bigint): Koinu {
  if (value < 0n || value > MAX_KOINU) {
    throw new RangeError(`koinu amount out of range: ${value}`);
  }
  return value.toString(10);
}

export function koinuToBigInt(value: Koinu): bigint {
  if (!isKoinu(value)) {
    throw new RangeError(`invalid koinu amount: ${String(value)}`);
  }
  return BigInt(value);
}

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
  previousOutputValueKoinu?: Koinu | null;
  multisigThreshold?: number | null;
  multisigPublicKeysHex: string[];
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

export type UtxoSignerKind = "wif" | "xpriv-derivation";

export interface UtxoSigner {
  kind: UtxoSignerKind;
  wif?: string | null;
  xpriv?: Xpriv | null;
  derivationPath?: string | null;
}

export interface SpendableUtxo {
  txid: string;
  vout: number;
  previousOutputValueKoinu: Koinu;
  scriptPubkeyHex: string;
  kind: SigningInputKind;
  redeemScriptHex?: string | null;
  multisigThreshold?: number | null;
  multisigPublicKeysHex: string[];
  signers: UtxoSigner[];
  manuallySelected: boolean;
}

export type TransactionOutputKind = "address" | "op-return" | "expert-raw-script";

export interface TransactionOutput {
  kind: TransactionOutputKind;
  valueKoinu: Koinu;
  address?: string | null;
  opReturnDataHex?: string | null;
  scriptHex?: string | null;
}

export interface FeePolicy {
  feeRateKoinuPerKb: Koinu;
  dustThresholdKoinu: Koinu;
}

export type CoinSelectionStrategy =
  | "min-inputs"
  | "smallest-first"
  | "largest-first"
  | "manual-selected-inputs";

export interface ChangeDestination {
  address?: string | null;
  xpriv?: Xpriv | null;
  derivationPath?: string | null;
}

export interface TransactionOptions {
  version: number;
  lockTime: number;
  sequence: number;
  sighashType: number;
}

export interface ComposeTransactionRequest {
  network: Network;
  utxos: SpendableUtxo[];
  outputs: TransactionOutput[];
  feePolicy: FeePolicy;
  coinSelection: CoinSelectionStrategy;
  change?: ChangeDestination | null;
  options: TransactionOptions;
}

export interface AuditedInput {
  txid: string;
  vout: number;
  previousOutputValueKoinu: Koinu;
  scriptPubkeyHex: string;
  kind: SigningInputKind;
}

export interface SkippedInput {
  txid: string;
  vout: number;
  previousOutputValueKoinu: Koinu;
  reason: string;
}

export interface ComposeTransactionResult {
  network: Network;
  selectedInputs: AuditedInput[];
  skippedInputs: SkippedInput[];
  inputTotalKoinu: Koinu;
  spendOutputTotalKoinu: Koinu;
  changeAmountKoinu: Koinu;
  changeAddress?: string | null;
  changeScriptPubkeyHex?: string | null;
  feeKoinu: Koinu;
  estimatedSizeBytes: number;
  actualSizeBytes?: number | null;
  dustChangeFoldedIntoFee: boolean;
  unsignedTxHex: string;
  signedTxHex?: string | null;
  signingEnvelope?: SigningEnvelope | null;
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
  composeAndSignTransaction(request: ComposeTransactionRequest): Promise<ComposeTransactionResult>;
  storeMnemonic(phrase: string, protection: StoredWalletProtection): Promise<StoredWalletHandle>;
  exportMnemonic(handle: StoredWalletHandle, protection: StoredWalletProtection): Promise<string>;
  protectionLevel(handle: StoredWalletHandle): Promise<StorageProtectionLevel>;
}

const EasyDogeKM = requireNativeModule<EasyDogeKMModule>("EasyDogeKM");
export default EasyDogeKM;

import { requireNativeModule } from "expo-modules-core";
