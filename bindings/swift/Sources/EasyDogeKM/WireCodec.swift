import Foundation

/// Raised when a JavaScript-facing value cannot be converted losslessly.
public enum WireCodecError: Error, Equatable, LocalizedError {
    case invalidKoinu(field: String)
    case invalidInteger(field: String, range: String)
    case unrepresentable(field: String)

    public var errorDescription: String? {
        switch self {
        case let .invalidKoinu(field):
            return "Invalid \(field): koinu amounts must be a canonical decimal string between 0 and 18446744073709551615"
        case let .invalidInteger(field, range):
            return "Invalid \(field): expected an integer in \(range)"
        case let .unrepresentable(field):
            return "Cannot return \(field): value exceeds JavaScript's safe integer range"
        }
    }
}

/// Lossless conversions between JavaScript-facing values and Rust integer types.
public enum WireCodec {
    public static let maxSafeInteger: UInt64 = 9_007_199_254_740_991

    public static func koinu(_ value: Any?, field: String) throws -> UInt64 {
        guard let text = value as? String, isCanonicalDecimal(text), let parsed = UInt64(text) else {
            throw WireCodecError.invalidKoinu(field: field)
        }
        return parsed
    }

    public static func optionalKoinu(_ value: Any?, field: String) throws -> UInt64? {
        if value == nil || value is NSNull { return nil }
        return try koinu(value, field: field)
    }

    public static func koinuString(_ value: UInt64) -> String {
        String(value)
    }

    public static func uint64(_ value: Any?, field: String) throws -> UInt64 {
        try integral(value, field: field, max: maxSafeInteger)
    }

    public static func uint32(_ value: Any?, field: String) throws -> UInt32 {
        UInt32(try integral(value, field: field, max: UInt64(UInt32.max)))
    }

    public static func uint16(_ value: Any?, field: String) throws -> UInt16 {
        UInt16(try integral(value, field: field, max: UInt64(UInt16.max)))
    }

    public static func uint8(_ value: Any?, field: String) throws -> UInt8 {
        UInt8(try integral(value, field: field, max: UInt64(UInt8.max)))
    }

    public static func optionalUInt8(_ value: Any?, field: String) throws -> UInt8? {
        if value == nil || value is NSNull { return nil }
        return try uint8(value, field: field)
    }

    public static func int32(_ value: Any?, field: String) throws -> Int32 {
        Int32(try integral(value, field: field, max: UInt64(Int32.max)))
    }

    public static func safeInteger(_ value: UInt64, field: String) throws -> Int {
        guard value <= maxSafeInteger else { throw WireCodecError.unrepresentable(field: field) }
        return Int(value)
    }

    private static func isCanonicalDecimal(_ text: String) -> Bool {
        guard !text.isEmpty, text.count <= 20, text.allSatisfy({ $0.isASCII && $0.isNumber }) else {
            return false
        }
        return text == "0" || !text.hasPrefix("0")
    }

    private static func integral(_ value: Any?, field: String, max: UInt64) throws -> UInt64 {
        let range = "0...\(max)"
        if value is Bool { throw WireCodecError.invalidInteger(field: field, range: range) }
        let double: Double
        switch value {
        case let int as Int:
            guard int >= 0, UInt64(int) <= max else { throw WireCodecError.invalidInteger(field: field, range: range) }
            return UInt64(int)
        case let value as Double:
            double = value
        case let number as NSNumber:
            double = number.doubleValue
        default:
            throw WireCodecError.invalidInteger(field: field, range: range)
        }
        guard double.isFinite, double >= 0, double.rounded(.towardZero) == double, double <= Double(max) else {
            throw WireCodecError.invalidInteger(field: field, range: range)
        }
        return UInt64(double)
    }
}
