package io.easydoge.km

/** Raised when a JavaScript-facing value cannot be converted losslessly. */
class WireCodecException(message: String) : IllegalArgumentException(message)

/** Lossless conversions between JavaScript-facing values and Rust integer types. */
object WireCodec {
    const val MAX_SAFE_INTEGER: Long = 9_007_199_254_740_991L
    private val CANONICAL_DECIMAL = Regex("0|[1-9][0-9]*")

    fun koinu(value: Any?, field: String): ULong {
        val text = value as? String
        if (text == null || text.length > 20 || !CANONICAL_DECIMAL.matches(text)) {
            throw invalidKoinu(field)
        }
        return text.toULongOrNull() ?: throw invalidKoinu(field)
    }

    fun optionalKoinu(value: Any?, field: String): ULong? = if (value == null) null else koinu(value, field)

    fun koinuString(value: ULong): String = value.toString()

    fun uint64(value: Any?, field: String): ULong = integral(value, field, MAX_SAFE_INTEGER).toULong()

    fun uint32(value: Any?, field: String): UInt = integral(value, field, UInt.MAX_VALUE.toLong()).toUInt()

    fun uint16(value: Any?, field: String): UShort = integral(value, field, UShort.MAX_VALUE.toLong()).toUShort()

    fun uint8(value: Any?, field: String): UByte = integral(value, field, UByte.MAX_VALUE.toLong()).toUByte()

    fun optionalUInt8(value: Any?, field: String): UByte? = if (value == null) null else uint8(value, field)

    fun int32(value: Any?, field: String): Int = integral(value, field, Int.MAX_VALUE.toLong()).toInt()

    fun safeInteger(value: ULong, field: String): Long {
        if (value > MAX_SAFE_INTEGER.toULong()) {
            throw WireCodecException("Cannot return $field: value exceeds JavaScript's safe integer range")
        }
        return value.toLong()
    }

    private fun invalidKoinu(field: String) =
        WireCodecException("Invalid $field: koinu amounts must be a canonical decimal string between 0 and 18446744073709551615")

    private fun integral(value: Any?, field: String, max: Long): Long {
        val range = "0...$max"
        val invalid = { WireCodecException("Invalid $field: expected an integer in $range") }
        return when (value) {
            is Boolean -> throw invalid()
            is Int, is Long, is Short, is Byte -> {
                val long = (value as Number).toLong()
                if (long < 0 || long > max) throw invalid()
                long
            }
            is Number -> {
                val double = value.toDouble()
                if (!double.isFinite() || double < 0 || double != Math.floor(double) || double > max.toDouble()) {
                    throw invalid()
                }
                double.toLong()
            }
            else -> throw invalid()
        }
    }
}
