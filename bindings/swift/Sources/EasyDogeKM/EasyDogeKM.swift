import Foundation
@_exported import easydoge_km_ffi

public enum StoredWalletProtection: Sendable, Equatable {
    case noPrompt
    case deviceCredential
    case biometric
}

public enum StorageProtectionLevel: Sendable, Equatable {
    case hardwareBacked
    case osBacked
    case unsupported
}

public struct StoredWalletHandle: Sendable, Equatable, Hashable {
    public let id: String

    public init(id: String) {
        self.id = id
    }
}

public protocol WalletSecretStore: Sendable {
    func storeMnemonic(
        _ mnemonic: String,
        protection: StoredWalletProtection
    ) async throws -> StoredWalletHandle

    func exportMnemonic(
        handle: StoredWalletHandle,
        protection: StoredWalletProtection
    ) async throws -> String

    func protectionLevel(handle: StoredWalletHandle) async throws -> StorageProtectionLevel
}

public struct EasyDogeKM: Sendable {
    public init() {}

    public func generateMnemonic(options: MnemonicOptions = MnemonicOptions(language: .english, wordCount: 24)) throws -> GeneratedMnemonic {
        try easydoge_km_ffi.generateMnemonic(options: options)
    }

    public func validateMnemonic(
        phrase: String,
        language: Language = .english
    ) throws -> Bool {
        try easydoge_km_ffi.validateMnemonic(phrase: phrase, language: language)
    }

    public func mnemonicToSeedHex(
        phrase: String,
        passphrase: String? = nil,
        language: Language = .english
    ) throws -> String {
        try easydoge_km_ffi.mnemonicToSeedHex(phrase: phrase, passphrase: passphrase, language: language)
    }

    public func accountKeys(
        phrase: String,
        passphrase: String?,
        language: Language = .english,
        network: Network = .mainnet,
        account: UInt32 = 0
    ) throws -> AccountKeySet {
        try easydoge_km_ffi.accountXprivFromMnemonic(
            phrase: phrase,
            passphrase: passphrase,
            language: language,
            network: network,
            account: account
        )
    }

    public func derivePathFromXpriv(xpriv: Xpriv, path: String) throws -> Xpriv {
        try easydoge_km_ffi.derivePathFromXpriv(xpriv: xpriv, path: path)
    }

    public func derivePathFromXpub(xpub: Xpub, path: String) throws -> Xpub {
        try easydoge_km_ffi.derivePathFromXpub(xpub: xpub, path: path)
    }

    public func xpubFromXpriv(xpriv: Xpriv) throws -> Xpub {
        try easydoge_km_ffi.xpubFromXpriv(xpriv: xpriv)
    }

    public func deriveAddressFromXpriv(xpriv: Xpriv, path: String) throws -> PathAddress {
        try easydoge_km_ffi.deriveAddressFromXpriv(xpriv: xpriv, path: path)
    }

    public func deriveAddressFromXpub(xpub: Xpub, path: String) throws -> PathAddress {
        try easydoge_km_ffi.deriveAddressFromXpub(xpub: xpub, path: path)
    }

    public func inspectXpriv(xpriv: Xpriv) throws -> ExtendedKeyInfo {
        try easydoge_km_ffi.inspectXpriv(xpriv: xpriv)
    }

    public func inspectXpub(xpub: Xpub) throws -> ExtendedKeyInfo {
        try easydoge_km_ffi.inspectXpub(xpub: xpub)
    }

    public func wifFromXpriv(xpriv: Xpriv) throws -> String {
        try easydoge_km_ffi.wifFromXpriv(xpriv: xpriv)
    }

    public func addressFromWif(network: Network = .mainnet, wif: String) throws -> WifInfo {
        try easydoge_km_ffi.addressFromWif(network: network, wif: wif)
    }

    public func validateAddress(network: Network = .mainnet, address: String) throws -> Bool {
        try easydoge_km_ffi.validateAddress(network: network, address: address)
    }

    public func createMultisigDescriptor(
        network: Network = .mainnet,
        threshold: UInt8,
        cosignerXpubs: [Xpub],
        childPath: String,
        sorted: Bool = true
    ) throws -> MultisigDescriptor {
        try easydoge_km_ffi.createMultisigDescriptor(
            network: network,
            threshold: threshold,
            cosignerXpubs: cosignerXpubs,
            childPath: childPath,
            sorted: sorted
        )
    }

    public func signMessage(
        network: Network = .mainnet,
        wif: String,
        message: String
    ) throws -> MessageSignature {
        try easydoge_km_ffi.signMessage(network: network, wif: wif, message: message)
    }

    public func verifyMessage(
        network: Network = .mainnet,
        address: String,
        signatureBase64: String,
        message: String
    ) throws -> Bool {
        try easydoge_km_ffi.verifyMessage(
            network: network,
            address: address,
            signatureBase64: signatureBase64,
            message: message
        )
    }

    public func signP2pkhTransaction(
        network: Network = .mainnet,
        unsignedTxHex: String,
        inputIndex: UInt64,
        scriptPubkeyHex: String,
        wif: String,
        sighashType: UInt32 = 1
    ) throws -> SignedTransaction {
        try easydoge_km_ffi.signP2pkhTransaction(
            network: network,
            unsignedTxHex: unsignedTxHex,
            inputIndex: inputIndex,
            scriptPubkeyHex: scriptPubkeyHex,
            wif: wif,
            sighashType: sighashType
        )
    }

    public func signSigningEnvelope(envelope: SigningEnvelope, wif: String) throws -> SigningEnvelope {
        try easydoge_km_ffi.signSigningEnvelope(envelope: envelope, wif: wif)
    }

    public func combineSigningEnvelopes(envelopes: [SigningEnvelope]) throws -> SigningEnvelope {
        try easydoge_km_ffi.combineSigningEnvelopes(envelopes: envelopes)
    }

    public func finalizeSigningEnvelope(envelope: SigningEnvelope) throws -> SignedTransaction {
        try easydoge_km_ffi.finalizeSigningEnvelope(envelope: envelope)
    }

    public func composeAndSignTransaction(request: ComposeTransactionRequest) throws -> ComposeTransactionResult {
        try easydoge_km_ffi.composeAndSignTransaction(request: request)
    }
}
