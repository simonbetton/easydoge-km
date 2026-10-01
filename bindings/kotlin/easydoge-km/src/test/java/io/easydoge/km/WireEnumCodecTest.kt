package io.easydoge.km

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import uniffi.easydoge_km_ffi.Language
import uniffi.easydoge_km_ffi.Network

class WireEnumCodecTest {
    private val networkNames = listOf("mainnet", "testnet", "regtest")
    private val languageNames = listOf(
        "english", "simplified-chinese", "traditional-chinese", "czech", "french",
        "italian", "japanese", "korean", "portuguese", "spanish",
    )
    private val protectionNames = listOf("no-prompt", "device-credential", "biometric")

    @Test
    fun networkRoundTripsEveryCaseAndRejectsEverythingElse() {
        assertEquals(Network.values().toList(), networkNames.map { WireEnumCodec.network(it, "network") })
        for (bad in listOf("", "Mainnet", "MAINNET", "main", "test", "local", " mainnet", "mainnet ", "not-a-network")) {
            assertFailsWith<WireCodecException> { WireEnumCodec.network(bad, "network") }
        }
        for (bad in listOf<Any?>(1, 1.0, true, listOf("mainnet"), null)) {
            assertFailsWith<WireCodecException> { WireEnumCodec.network(bad, "network") }
        }
    }

    @Test
    fun languageDefaultsToEnglishOnlyWhenAbsent() {
        assertEquals(Language.values().toList(), languageNames.map { WireEnumCodec.language(it, "language") })
        assertEquals(Language.ENGLISH, WireEnumCodec.language(null, "language"))
        for (bad in listOf("", "English", "en", "ja", "simplifiedChinese", "simplified_chinese", "chinese", "not-a-language")) {
            assertFailsWith<WireCodecException> { WireEnumCodec.language(bad, "language") }
        }
        for (bad in listOf<Any>(1, true, listOf("english"))) {
            assertFailsWith<WireCodecException> { WireEnumCodec.language(bad, "language") }
        }
    }

    @Test
    fun protectionNeverFallsBackToNoPrompt() {
        assertEquals(
            StoredWalletProtection.values().toList(),
            protectionNames.map { WireEnumCodec.protection(it, "protection") },
        )
        for (bad in listOf("", "Biometric", "biometrics", "noPrompt", "no_prompt", "deviceCredential", "none", "not-a-protection")) {
            assertFailsWith<WireCodecException> { WireEnumCodec.protection(bad, "protection") }
        }
        for (bad in listOf<Any?>(0, false, null)) {
            assertFailsWith<WireCodecException> { WireEnumCodec.protection(bad, "protection") }
        }
    }

    @Test
    fun rejectionMessagesListAllowedNamesAndNeverEchoTheInput() {
        val network = assertFailsWith<WireCodecException> { WireEnumCodec.network("not-a-network", "network") }
        assertEquals("Invalid network: expected one of mainnet, testnet, regtest", network.message)
        val language = assertFailsWith<WireCodecException> { WireEnumCodec.language("not-a-language", "language") }
        assertEquals(
            "Invalid language: expected one of english, simplified-chinese, traditional-chinese, czech, french, italian, japanese, korean, portuguese, spanish",
            language.message,
        )
        val protection = assertFailsWith<WireCodecException> { WireEnumCodec.protection("not-a-protection", "protection") }
        assertEquals("Invalid protection: expected one of no-prompt, device-credential, biometric", protection.message)
        assertFalse(protection.toString().contains("not-a-protection"))
    }
}
