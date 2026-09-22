import Foundation
import Testing
@testable import EasyDogeKM

@Suite struct WireCodecTests {
    @Test func koinuAcceptsCanonicalDecimalStringsOnly() throws {
        #expect(try WireCodec.koinu("0", field: "valueKoinu") == 0)
        #expect(try WireCodec.koinu("18446744073709551615", field: "valueKoinu") == UInt64.max)
        #expect(try WireCodec.koinu("9007199254740993", field: "valueKoinu") == 9_007_199_254_740_993)
        for bad in ["", "01", "-1", "1.0", "1e3", " 1", "18446744073709551616", "abc"] as [Any] {
            #expect(throws: WireCodecError.self) { try WireCodec.koinu(bad, field: "valueKoinu") }
        }
        #expect(throws: WireCodecError.self) { try WireCodec.koinu(1 as Int, field: "valueKoinu") }
        #expect(throws: WireCodecError.self) { try WireCodec.koinu(nil, field: "valueKoinu") }
        #expect(try WireCodec.optionalKoinu(nil, field: "x") == nil)
        #expect(try WireCodec.optionalKoinu("7", field: "x") == 7)
        #expect(WireCodec.koinuString(UInt64.max) == "18446744073709551615")
    }

    @Test func integersAreRangeCheckedAndNeverTrap() throws {
        #expect(try WireCodec.uint32(4294967295.0, field: "vout") == UInt32.max)
        #expect(try WireCodec.uint32(7 as Int, field: "vout") == 7)
        #expect(try WireCodec.uint8(255.0, field: "threshold") == 255)
        #expect(try WireCodec.uint16(24 as Int, field: "wordCount") == 24)
        #expect(try WireCodec.int32(1.0, field: "version") == 1)
        #expect(try WireCodec.uint64(9007199254740991.0, field: "inputIndex") == 9_007_199_254_740_991)
        for bad in [-1.0, 1.5, Double.nan, Double.infinity, 4294967296.0] {
            #expect(throws: WireCodecError.self) { try WireCodec.uint32(bad, field: "vout") }
        }
        #expect(throws: WireCodecError.self) { try WireCodec.uint8(256.0, field: "threshold") }
        #expect(throws: WireCodecError.self) { try WireCodec.uint32(true, field: "vout") }
        #expect(throws: WireCodecError.self) { try WireCodec.uint32("1", field: "vout") }
        #expect(throws: WireCodecError.self) { try WireCodec.uint32(nil, field: "vout") }
        #expect(throws: WireCodecError.self) { try WireCodec.uint64(9007199254740992.0, field: "inputIndex") }
        #expect(try WireCodec.safeInteger(42, field: "estimatedSizeBytes") == 42)
        #expect(throws: WireCodecError.self) { try WireCodec.safeInteger(UInt64.max, field: "estimatedSizeBytes") }
    }
}
