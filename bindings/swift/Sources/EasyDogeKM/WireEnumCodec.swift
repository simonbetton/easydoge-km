import Foundation

/// Strict parsers for the string enums that cross the JavaScript bridge.
///
/// Only the canonical kebab-case names declared by the Expo TypeScript unions
/// are accepted, case-sensitively and without aliases. Anything else throws
/// `WireCodecError.invalidEnum`; nothing falls back to a default. The error
/// lists the allowed names and never carries the rejected value, which could
/// be a secret passed in the wrong argument position.
public enum WireEnumCodec {
    private static let networks: [(name: String, value: Network)] = [
        ("mainnet", .mainnet),
        ("testnet", .testnet),
        ("regtest", .regtest)
    ]

    private static let languages: [(name: String, value: Language)] = [
        ("english", .english),
        ("simplified-chinese", .simplifiedChinese),
        ("traditional-chinese", .traditionalChinese),
        ("czech", .czech),
        ("french", .french),
        ("italian", .italian),
        ("japanese", .japanese),
        ("korean", .korean),
        ("portuguese", .portuguese),
        ("spanish", .spanish)
    ]

    private static let protections: [(name: String, value: StoredWalletProtection)] = [
        ("no-prompt", .noPrompt),
        ("device-credential", .deviceCredential),
        ("biometric", .biometric)
    ]

    /// Required: absent, null, non-string, and unknown values all throw.
    public static func network(_ value: Any?, field: String) throws -> Network {
        try lookup(value, in: networks, field: field)
    }

    /// Optional: absent or null means English, the documented default. A
    /// non-string or unknown string throws.
    public static func language(_ value: Any?, field: String) throws -> Language {
        if value == nil || value is NSNull { return .english }
        return try lookup(value, in: languages, field: field)
    }

    /// Required: absent, null, non-string, and unknown values all throw.
    public static func protection(_ value: Any?, field: String) throws -> StoredWalletProtection {
        try lookup(value, in: protections, field: field)
    }

    private static func lookup<T>(_ value: Any?, in table: [(name: String, value: T)], field: String) throws -> T {
        guard let text = value as? String, let match = table.first(where: { $0.name == text }) else {
            throw WireCodecError.invalidEnum(field: field, allowed: table.map { $0.name })
        }
        return match.value
    }
}
