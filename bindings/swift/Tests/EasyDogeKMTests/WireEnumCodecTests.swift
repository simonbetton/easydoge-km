import Foundation
import Testing
@testable import EasyDogeKM

@Suite struct WireEnumCodecTests {
    private let networkNames = ["mainnet", "testnet", "regtest"]
    private let languageNames = [
        "english", "simplified-chinese", "traditional-chinese", "czech", "french",
        "italian", "japanese", "korean", "portuguese", "spanish"
    ]
    private let protectionNames = ["no-prompt", "device-credential", "biometric"]

    @Test func networkRoundTripsEveryCaseAndRejectsEverythingElse() throws {
        for name in networkNames {
            #expect(wireName(try WireEnumCodec.network(name, field: "network")) == name)
        }
        let expected = WireCodecError.invalidEnum(field: "network", allowed: networkNames)
        for bad in ["", "Mainnet", "MAINNET", "main", "test", "local", " mainnet", "mainnet ", "not-a-network"] {
            #expect(throws: expected) { try WireEnumCodec.network(bad, field: "network") }
        }
        for bad in [1 as Int, 1.0 as Double, true, NSNull(), ["mainnet"]] as [Any] {
            #expect(throws: expected) { try WireEnumCodec.network(bad, field: "network") }
        }
        #expect(throws: expected) { try WireEnumCodec.network(nil, field: "network") }
    }

    @Test func languageDefaultsToEnglishOnlyWhenAbsent() throws {
        for name in languageNames {
            #expect(wireName(try WireEnumCodec.language(name, field: "language")) == name)
        }
        #expect(try WireEnumCodec.language(nil, field: "language") == .english)
        #expect(try WireEnumCodec.language(NSNull(), field: "language") == .english)
        let absent: String? = nil
        #expect(try WireEnumCodec.language(absent, field: "language") == .english)
        let expected = WireCodecError.invalidEnum(field: "language", allowed: languageNames)
        for bad in ["", "English", "en", "ja", "simplifiedChinese", "simplified_chinese", "chinese", "not-a-language"] {
            #expect(throws: expected) { try WireEnumCodec.language(bad, field: "language") }
        }
        for bad in [1 as Int, true, ["english"]] as [Any] {
            #expect(throws: expected) { try WireEnumCodec.language(bad, field: "language") }
        }
    }

    @Test func protectionNeverFallsBackToNoPrompt() throws {
        for name in protectionNames {
            #expect(wireName(try WireEnumCodec.protection(name, field: "protection")) == name)
        }
        let expected = WireCodecError.invalidEnum(field: "protection", allowed: protectionNames)
        for bad in ["", "Biometric", "biometrics", "noPrompt", "no_prompt", "deviceCredential", "none", "not-a-protection"] {
            #expect(throws: expected) { try WireEnumCodec.protection(bad, field: "protection") }
        }
        for bad in [0 as Int, false, NSNull()] as [Any] {
            #expect(throws: expected) { try WireEnumCodec.protection(bad, field: "protection") }
        }
        #expect(throws: expected) { try WireEnumCodec.protection(nil, field: "protection") }
    }

    @Test func rejectionMessagesListAllowedNamesAndNeverEchoTheInput() {
        #expect(
            WireCodecError.invalidEnum(field: "network", allowed: networkNames).errorDescription
                == "Invalid network: expected one of mainnet, testnet, regtest"
        )
        #expect(
            WireCodecError.invalidEnum(field: "language", allowed: languageNames).errorDescription
                == "Invalid language: expected one of english, simplified-chinese, traditional-chinese, czech, french, italian, japanese, korean, portuguese, spanish"
        )
        #expect(
            WireCodecError.invalidEnum(field: "protection", allowed: protectionNames).errorDescription
                == "Invalid protection: expected one of no-prompt, device-credential, biometric"
        )
        do {
            _ = try WireEnumCodec.protection("not-a-protection", field: "protection")
            Issue.record("expected WireEnumCodec.protection to throw")
        } catch {
            #expect(error.localizedDescription == "Invalid protection: expected one of no-prompt, device-credential, biometric")
            #expect(!String(describing: error).contains("not-a-protection"))
        }
    }
}

// Exhaustive switches: a new enum case fails to compile here until the wire
// name is added both below and in WireEnumCodec.
private func wireName(_ value: Network) -> String {
    switch value {
    case .mainnet: return "mainnet"
    case .testnet: return "testnet"
    case .regtest: return "regtest"
    }
}

private func wireName(_ value: Language) -> String {
    switch value {
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

private func wireName(_ value: StoredWalletProtection) -> String {
    switch value {
    case .noPrompt: return "no-prompt"
    case .deviceCredential: return "device-credential"
    case .biometric: return "biometric"
    }
}
