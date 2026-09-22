package io.easydoge.km

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull

class WireCodecTest {
    @Test
    fun koinuAcceptsCanonicalDecimalStringsOnly() {
        assertEquals(0uL, WireCodec.koinu("0", "valueKoinu"))
        assertEquals(ULong.MAX_VALUE, WireCodec.koinu("18446744073709551615", "valueKoinu"))
        assertEquals(9_007_199_254_740_993uL, WireCodec.koinu("9007199254740993", "valueKoinu"))
        for (bad in listOf("", "01", "-1", "1.0", "1e3", " 1", "18446744073709551616", "abc")) {
            assertFailsWith<WireCodecException> { WireCodec.koinu(bad, "valueKoinu") }
        }
        assertFailsWith<WireCodecException> { WireCodec.koinu(1, "valueKoinu") }
        assertFailsWith<WireCodecException> { WireCodec.koinu(null, "valueKoinu") }
        assertNull(WireCodec.optionalKoinu(null, "x"))
        assertEquals(7uL, WireCodec.optionalKoinu("7", "x"))
        assertEquals("18446744073709551615", WireCodec.koinuString(ULong.MAX_VALUE))
    }

    @Test
    fun integersAreRangeCheckedAndNeverWrap() {
        assertEquals(UInt.MAX_VALUE, WireCodec.uint32(4294967295.0, "vout"))
        assertEquals(7u, WireCodec.uint32(7, "vout"))
        assertEquals(255u.toUByte(), WireCodec.uint8(255.0, "threshold"))
        assertEquals(24u.toUShort(), WireCodec.uint16(24, "wordCount"))
        assertEquals(1, WireCodec.int32(1.0, "version"))
        assertEquals(9_007_199_254_740_991uL, WireCodec.uint64(9007199254740991.0, "inputIndex"))
        for (bad in listOf(-1.0, 1.5, Double.NaN, Double.POSITIVE_INFINITY, 4294967296.0)) {
            assertFailsWith<WireCodecException> { WireCodec.uint32(bad, "vout") }
        }
        assertFailsWith<WireCodecException> { WireCodec.uint8(256.0, "threshold") }
        assertFailsWith<WireCodecException> { WireCodec.uint8(300, "threshold") }
        assertFailsWith<WireCodecException> { WireCodec.uint32(true, "vout") }
        assertFailsWith<WireCodecException> { WireCodec.uint32("1", "vout") }
        assertFailsWith<WireCodecException> { WireCodec.uint32(null, "vout") }
        assertFailsWith<WireCodecException> { WireCodec.uint64(9007199254740992.0, "inputIndex") }
        assertEquals(42L, WireCodec.safeInteger(42uL, "estimatedSizeBytes"))
        assertFailsWith<WireCodecException> { WireCodec.safeInteger(ULong.MAX_VALUE, "estimatedSizeBytes") }
    }
}
