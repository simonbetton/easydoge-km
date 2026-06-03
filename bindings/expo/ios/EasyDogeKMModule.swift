import ExpoModulesCore
import EasyDogeKM

public class EasyDogeKMModule: Module {
    private let sdk = EasyDogeKM()
    private let store = KeychainWalletSecretStore()

    public func definition() -> ModuleDefinition {
        Name("EasyDogeKM")

        AsyncFunction("generateMnemonic") { (options: [String: Any]?) in
            let opts = MnemonicOptions(
                language: parseLanguage(options?["language"] as? String),
                wordCount: UInt16(options?["wordCount"] as? Int ?? 24)
            )
            return try sdk.generateMnemonic(options: opts).asDictionary()
        }

        AsyncFunction("validateMnemonic") { (phrase: String, language: String?) in
            try validateMnemonic(phrase: phrase, language: parseLanguage(language))
        }

        AsyncFunction("mnemonicToSeedHex") { (phrase: String, passphrase: String?, language: String?) in
            try mnemonicToSeedHex(phrase: phrase, passphrase: passphrase, language: parseLanguage(language))
        }

        AsyncFunction("accountKeysFromMnemonic") { (phrase: String, passphrase: String?, language: String, network: String, account: Int) in
            try sdk.accountKeys(
                phrase: phrase,
                passphrase: passphrase,
                language: parseLanguage(language),
                network: parseNetwork(network),
                account: UInt32(account)
            ).asDictionary()
        }

        AsyncFunction("deriveAddressFromXpriv") { (xpriv: [String: String], path: String) in
            try deriveAddressFromXpriv(xpriv: Xpriv.fromDictionary(xpriv), path: path).asDictionary()
        }

        AsyncFunction("deriveAddressFromXpub") { (xpub: [String: String], path: String) in
            try deriveAddressFromXpub(xpub: Xpub.fromDictionary(xpub), path: path).asDictionary()
        }

        AsyncFunction("derivePathFromXpriv") { (xpriv: [String: String], path: String) in
            try derivePathFromXpriv(xpriv: Xpriv.fromDictionary(xpriv), path: path).asDictionary()
        }

        AsyncFunction("derivePathFromXpub") { (xpub: [String: String], path: String) in
            try derivePathFromXpub(xpub: Xpub.fromDictionary(xpub), path: path).asDictionary()
        }

        AsyncFunction("xpubFromXpriv") { (xpriv: [String: String]) in
            try xpubFromXpriv(xpriv: Xpriv.fromDictionary(xpriv)).asDictionary()
        }

        AsyncFunction("wifFromXpriv") { (xpriv: [String: String]) in
            try wifFromXpriv(xpriv: Xpriv.fromDictionary(xpriv))
        }

        AsyncFunction("addressFromWif") { (network: String, wif: String) in
            try addressFromWif(network: parseNetwork(network), wif: wif).asDictionary()
        }

        AsyncFunction("validateAddress") { (network: String, address: String) in
            try validateAddress(network: parseNetwork(network), address: address)
        }

        AsyncFunction("storeMnemonic") { (phrase: String, protection: String) async throws in
            try await store.storeMnemonic(phrase, protection: parseProtection(protection)).asDictionary()
        }

        AsyncFunction("exportMnemonic") { (handle: [String: String], protection: String) async throws in
            try await store.exportMnemonic(
                handle: StoredWalletHandle(id: handle["id"] ?? ""),
                protection: parseProtection(protection)
            )
        }

        AsyncFunction("protectionLevel") { (handle: [String: String]) async throws in
            try await store.protectionLevel(handle: StoredWalletHandle(id: handle["id"] ?? "")).rawValue
        }
    }
}

private func parseNetwork(_ value: String?) -> Network {
    switch value {
    case "testnet": return .testnet
    case "regtest": return .regtest
    default: return .mainnet
    }
}

private func parseLanguage(_ value: String?) -> Language {
    switch value {
    case "simplified-chinese": return .simplifiedChinese
    case "traditional-chinese": return .traditionalChinese
    case "czech": return .czech
    case "french": return .french
    case "italian": return .italian
    case "japanese": return .japanese
    case "korean": return .korean
    case "portuguese": return .portuguese
    case "spanish": return .spanish
    default: return .english
    }
}

private func parseProtection(_ value: String) -> StoredWalletProtection {
    switch value {
    case "device-credential": return .deviceCredential
    case "biometric": return .biometric
    default: return .noPrompt
    }
}

private extension StorageProtectionLevel {
    var rawValue: String {
        switch self {
        case .hardwareBacked: return "hardware-backed"
        case .osBacked: return "os-backed"
        case .unsupported: return "unsupported"
        }
    }
}

private extension StoredWalletHandle {
    func asDictionary() -> [String: String] {
        ["id": id]
    }
}

private extension GeneratedMnemonic {
    func asDictionary() -> [String: Any] {
        ["phrase": phrase, "language": language.rawString, "wordCount": Int(wordCount)]
    }
}

private extension AccountKeySet {
    func asDictionary() -> [String: Any] {
        [
            "network": network.rawString,
            "account": Int(account),
            "accountPath": accountPath,
            "xpriv": xpriv.asDictionary(),
            "xpub": xpub.asDictionary()
        ]
    }
}

private extension PathAddress {
    func asDictionary() -> [String: Any] {
        [
            "network": network.rawString,
            "path": path,
            "publicKeyHex": publicKeyHex,
            "address": address
        ]
    }
}

private extension Xpriv {
    static func fromDictionary(_ value: [String: String]) -> Xpriv {
        Xpriv(network: parseNetwork(value["network"]), encoded: value["encoded"] ?? "")
    }

    func asDictionary() -> [String: String] {
        ["network": network.rawString, "encoded": encoded]
    }
}

private extension Xpub {
    static func fromDictionary(_ value: [String: String]) -> Xpub {
        Xpub(network: parseNetwork(value["network"]), encoded: value["encoded"] ?? "")
    }

    func asDictionary() -> [String: String] {
        ["network": network.rawString, "encoded": encoded]
    }
}

private extension WifInfo {
    func asDictionary() -> [String: Any] {
        [
            "network": network.rawString,
            "publicKeyHex": publicKeyHex,
            "address": address,
            "compressed": compressed
        ]
    }
}

private extension Network {
    var rawString: String {
        switch self {
        case .mainnet: return "mainnet"
        case .testnet: return "testnet"
        case .regtest: return "regtest"
        }
    }
}

private extension Language {
    var rawString: String {
        switch self {
        case .english: return "english"
        case .simplifiedChinese: return "simplified-chinese"
        case .traditionalChinese: return "traditional-chinese"
        case .czech: return "czech"
        case .french: return "french"
        case .italian: return "italian"
        case .japanese: return "japanese"
        case .korean: return "korean"
        case .portuguese: return "portuguese"
        case .spanish: return "spanish"
        }
    }
}
