package io.easydoge.km

import uniffi.easydoge_km_ffi.AccountKeySet
import uniffi.easydoge_km_ffi.GeneratedMnemonic
import uniffi.easydoge_km_ffi.Language
import uniffi.easydoge_km_ffi.MnemonicOptions
import uniffi.easydoge_km_ffi.Network

data class StoredWalletHandle(val id: String)

enum class StoredWalletProtection {
    NoPrompt,
    DeviceCredential,
    Biometric,
}

enum class StorageProtectionLevel {
    HardwareBacked,
    OsBacked,
    Unsupported,
}

interface WalletSecretStore {
    suspend fun storeMnemonic(
        mnemonic: String,
        protection: StoredWalletProtection,
    ): StoredWalletHandle

    suspend fun exportMnemonic(
        handle: StoredWalletHandle,
        protection: StoredWalletProtection,
    ): String

    suspend fun protectionLevel(handle: StoredWalletHandle): StorageProtectionLevel
}

class EasyDogeKM {
    fun generateMnemonic(options: MnemonicOptions = MnemonicOptions(Language.ENGLISH, 24u)): GeneratedMnemonic =
        uniffi.easydoge_km_ffi.generateMnemonic(options)

    fun accountKeys(
        phrase: String,
        passphrase: String?,
        language: Language = Language.ENGLISH,
        network: Network = Network.MAINNET,
        account: UInt = 0u,
    ): AccountKeySet =
        uniffi.easydoge_km_ffi.accountXprivFromMnemonic(phrase, passphrase, language, network, account)
}
