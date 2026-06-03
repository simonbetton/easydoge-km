package io.easydoge.km.expo

import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import io.easydoge.km.AndroidKeystoreWalletSecretStore
import io.easydoge.km.EasyDogeKM
import io.easydoge.km.StoredWalletHandle
import io.easydoge.km.StoredWalletProtection
import uniffi.easydoge_km_ffi.Language
import uniffi.easydoge_km_ffi.MnemonicOptions
import uniffi.easydoge_km_ffi.Network
import uniffi.easydoge_km_ffi.Xpriv
import uniffi.easydoge_km_ffi.Xpub
import uniffi.easydoge_km_ffi.validateAddress
import uniffi.easydoge_km_ffi.validateMnemonic

class EasyDogeKMModule : Module() {
    private val sdk = EasyDogeKM()
    private val store = AndroidKeystoreWalletSecretStore()

    override fun definition() = ModuleDefinition {
        Name("EasyDogeKM")

        AsyncFunction("generateMnemonic") { options: Map<String, Any>? ->
            sdk.generateMnemonic(
                MnemonicOptions(
                    parseLanguage(options?.get("language") as? String),
                    ((options?.get("wordCount") as? Number)?.toInt() ?: 24).toUInt(),
                ),
            ).toMap()
        }

        AsyncFunction("validateMnemonic") { phrase: String, language: String? ->
            validateMnemonic(phrase, parseLanguage(language))
        }

        AsyncFunction("accountKeysFromMnemonic") { phrase: String, passphrase: String?, language: String, network: String, account: Int ->
            sdk.accountKeys(phrase, passphrase, parseLanguage(language), parseNetwork(network), account.toUInt()).toMap()
        }

        AsyncFunction("deriveAddressFromXpriv") { xpriv: Map<String, String>, path: String ->
            uniffi.easydoge_km_ffi.deriveAddressFromXpriv(xpriv.toXpriv(), path).toMap()
        }

        AsyncFunction("deriveAddressFromXpub") { xpub: Map<String, String>, path: String ->
            uniffi.easydoge_km_ffi.deriveAddressFromXpub(xpub.toXpub(), path).toMap()
        }

        AsyncFunction("derivePathFromXpriv") { xpriv: Map<String, String>, path: String ->
            uniffi.easydoge_km_ffi.derivePathFromXpriv(xpriv.toXpriv(), path).toMap()
        }

        AsyncFunction("derivePathFromXpub") { xpub: Map<String, String>, path: String ->
            uniffi.easydoge_km_ffi.derivePathFromXpub(xpub.toXpub(), path).toMap()
        }

        AsyncFunction("xpubFromXpriv") { xpriv: Map<String, String> ->
            uniffi.easydoge_km_ffi.xpubFromXpriv(xpriv.toXpriv()).toMap()
        }

        AsyncFunction("wifFromXpriv") { xpriv: Map<String, String> ->
            uniffi.easydoge_km_ffi.wifFromXpriv(xpriv.toXpriv())
        }

        AsyncFunction("addressFromWif") { network: String, wif: String ->
            uniffi.easydoge_km_ffi.addressFromWif(parseNetwork(network), wif).toMap()
        }

        AsyncFunction("validateAddress") { network: String, address: String ->
            validateAddress(parseNetwork(network), address)
        }

        AsyncFunction("storeMnemonic") { phrase: String, protection: String ->
            store.storeMnemonic(phrase, parseProtection(protection)).toMap()
        }

        AsyncFunction("exportMnemonic") { handle: Map<String, String>, protection: String ->
            store.exportMnemonic(StoredWalletHandle(handle["id"] ?: ""), parseProtection(protection))
        }

        AsyncFunction("protectionLevel") { handle: Map<String, String> ->
            when (store.protectionLevel(StoredWalletHandle(handle["id"] ?: ""))) {
                io.easydoge.km.StorageProtectionLevel.HardwareBacked -> "hardware-backed"
                io.easydoge.km.StorageProtectionLevel.OsBacked -> "os-backed"
                io.easydoge.km.StorageProtectionLevel.Unsupported -> "unsupported"
            }
        }
    }
}

private fun parseNetwork(value: String?): Network = when (value) {
    "testnet" -> Network.TESTNET
    "regtest" -> Network.REGTEST
    else -> Network.MAINNET
}

private fun parseLanguage(value: String?): Language = when (value) {
    "simplified-chinese" -> Language.SIMPLIFIED_CHINESE
    "traditional-chinese" -> Language.TRADITIONAL_CHINESE
    "czech" -> Language.CZECH
    "french" -> Language.FRENCH
    "italian" -> Language.ITALIAN
    "japanese" -> Language.JAPANESE
    "korean" -> Language.KOREAN
    "portuguese" -> Language.PORTUGUESE
    "spanish" -> Language.SPANISH
    else -> Language.ENGLISH
}

private fun parseProtection(value: String): StoredWalletProtection = when (value) {
    "device-credential" -> StoredWalletProtection.DeviceCredential
    "biometric" -> StoredWalletProtection.Biometric
    else -> StoredWalletProtection.NoPrompt
}

private fun StoredWalletHandle.toMap(): Map<String, String> = mapOf("id" to id)
private fun Map<String, String>.toXpriv(): Xpriv = Xpriv(parseNetwork(this["network"]), this["encoded"] ?: "")
private fun Map<String, String>.toXpub(): Xpub = Xpub(parseNetwork(this["network"]), this["encoded"] ?: "")

private fun uniffi.easydoge_km_ffi.GeneratedMnemonic.toMap(): Map<String, Any> =
    mapOf("phrase" to phrase, "language" to language.raw(), "wordCount" to wordCount.toInt())

private fun uniffi.easydoge_km_ffi.AccountKeySet.toMap(): Map<String, Any> =
    mapOf(
        "network" to network.raw(),
        "account" to account.toInt(),
        "accountPath" to accountPath,
        "xpriv" to xpriv.toMap(),
        "xpub" to xpub.toMap(),
    )

private fun uniffi.easydoge_km_ffi.PathAddress.toMap(): Map<String, Any> =
    mapOf("network" to network.raw(), "path" to path, "publicKeyHex" to publicKeyHex, "address" to address)

private fun Xpriv.toMap(): Map<String, String> = mapOf("network" to network.raw(), "encoded" to encoded)
private fun Xpub.toMap(): Map<String, String> = mapOf("network" to network.raw(), "encoded" to encoded)

private fun uniffi.easydoge_km_ffi.WifInfo.toMap(): Map<String, Any> =
    mapOf(
        "network" to network.raw(),
        "publicKeyHex" to publicKeyHex,
        "address" to address,
        "compressed" to compressed,
    )

private fun Network.raw(): String = when (this) {
    Network.MAINNET -> "mainnet"
    Network.TESTNET -> "testnet"
    Network.REGTEST -> "regtest"
}

private fun Language.raw(): String = when (this) {
    Language.ENGLISH -> "english"
    Language.SIMPLIFIED_CHINESE -> "simplified-chinese"
    Language.TRADITIONAL_CHINESE -> "traditional-chinese"
    Language.CZECH -> "czech"
    Language.FRENCH -> "french"
    Language.ITALIAN -> "italian"
    Language.JAPANESE -> "japanese"
    Language.KOREAN -> "korean"
    Language.PORTUGUESE -> "portuguese"
    Language.SPANISH -> "spanish"
}
