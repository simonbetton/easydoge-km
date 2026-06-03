import Foundation
import LocalAuthentication
import Security

public final actor KeychainWalletSecretStore: WalletSecretStore {
    private let service: String

    public init(service: String = "io.easydoge.km.wallet-secrets") {
        self.service = service
    }

    public func storeMnemonic(
        _ mnemonic: String,
        protection: StoredWalletProtection
    ) async throws -> StoredWalletHandle {
        let id = UUID().uuidString
        let data = Data(mnemonic.utf8)
        var query = baseQuery(account: id)
        query[kSecValueData as String] = data
        query[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        if let accessControl = try makeAccessControl(protection: protection) {
            query[kSecAttrAccessControl as String] = accessControl
            query.removeValue(forKey: kSecAttrAccessible as String)
        }

        SecItemDelete(query as CFDictionary)
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw KeychainWalletSecretStoreError.keychain(status)
        }
        return StoredWalletHandle(id: id)
    }

    public func exportMnemonic(
        handle: StoredWalletHandle,
        protection: StoredWalletProtection
    ) async throws -> String {
        var query = baseQuery(account: handle.id)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        if protection != .noPrompt {
            let context = LAContext()
            context.localizedReason = "Unlock Dogecoin wallet secret"
            query[kSecUseAuthenticationContext as String] = context
        }

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess else {
            throw KeychainWalletSecretStoreError.keychain(status)
        }
        guard let data = result as? Data, let mnemonic = String(data: data, encoding: .utf8) else {
            throw KeychainWalletSecretStoreError.invalidData
        }
        return mnemonic
    }

    public func protectionLevel(handle: StoredWalletHandle) async throws -> StorageProtectionLevel {
        var query = baseQuery(account: handle.id)
        query[kSecReturnAttributes as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess else {
            throw KeychainWalletSecretStoreError.keychain(status)
        }
        return .osBacked
    }

    private func baseQuery(account: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
    }

    private func makeAccessControl(protection: StoredWalletProtection) throws -> SecAccessControl? {
        guard protection != .noPrompt else { return nil }
        var error: Unmanaged<CFError>?
        let flags: SecAccessControlCreateFlags
        if protection == .biometric {
            if #available(iOS 11.3, macOS 10.13.4, *) {
                flags = [.biometryCurrentSet]
            } else {
                flags = [.userPresence]
            }
        } else {
            flags = [.userPresence]
        }
        guard let accessControl = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            flags,
            &error
        ) else {
            throw error?.takeRetainedValue() ?? KeychainWalletSecretStoreError.accessControl
        }
        return accessControl
    }
}

public enum KeychainWalletSecretStoreError: Error, Sendable, Equatable {
    case keychain(OSStatus)
    case accessControl
    case invalidData
}
