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
}
