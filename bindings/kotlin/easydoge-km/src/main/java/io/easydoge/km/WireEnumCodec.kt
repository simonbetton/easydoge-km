package io.easydoge.km

import uniffi.easydoge_km_ffi.Language
import uniffi.easydoge_km_ffi.Network

/**
 * Strict parsers for the string enums that cross the JavaScript bridge.
 *
 * Only the canonical kebab-case names declared by the Expo TypeScript unions
 * are accepted, case-sensitively and without aliases. Anything else throws
 * [WireCodecException]; nothing falls back to a default. The message lists the
 * allowed names and never includes the rejected value, which could be a secret
 * passed in the wrong argument position.
 */
object WireEnumCodec {
    private val NETWORKS = linkedMapOf(
        "mainnet" to Network.MAINNET,
        "testnet" to Network.TESTNET,
        "regtest" to Network.REGTEST,
    )

    private val LANGUAGES = linkedMapOf(
        "english" to Language.ENGLISH,
        "simplified-chinese" to Language.SIMPLIFIED_CHINESE,
        "traditional-chinese" to Language.TRADITIONAL_CHINESE,
        "czech" to Language.CZECH,
        "french" to Language.FRENCH,
        "italian" to Language.ITALIAN,
        "japanese" to Language.JAPANESE,
        "korean" to Language.KOREAN,
        "portuguese" to Language.PORTUGUESE,
        "spanish" to Language.SPANISH,
    )

    private val PROTECTIONS = linkedMapOf(
        "no-prompt" to StoredWalletProtection.NoPrompt,
        "device-credential" to StoredWalletProtection.DeviceCredential,
        "biometric" to StoredWalletProtection.Biometric,
    )

    /** Required: null, non-string, and unknown values all throw. */
    fun network(value: Any?, field: String): Network = lookup(value, NETWORKS, field)

    /**
     * Optional: null (absent) means English, the documented default. A
     * non-string or unknown string throws.
     */
    fun language(value: Any?, field: String): Language =
        if (value == null) Language.ENGLISH else lookup(value, LANGUAGES, field)

    /** Required: null, non-string, and unknown values all throw. */
    fun protection(value: Any?, field: String): StoredWalletProtection = lookup(value, PROTECTIONS, field)

    private fun <T : Any> lookup(value: Any?, table: Map<String, T>, field: String): T =
        (value as? String)?.let { table[it] }
            ?: throw WireCodecException("Invalid $field: expected one of ${table.keys.joinToString(", ")}")
}
