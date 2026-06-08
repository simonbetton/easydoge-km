package io.easydoge.km

import uniffi.easydoge_km_ffi.AccountKeySet
import uniffi.easydoge_km_ffi.ExtendedKeyInfo
import uniffi.easydoge_km_ffi.GeneratedMnemonic
import uniffi.easydoge_km_ffi.Language
import uniffi.easydoge_km_ffi.MessageSignature
import uniffi.easydoge_km_ffi.MnemonicOptions
import uniffi.easydoge_km_ffi.MultisigDescriptor
import uniffi.easydoge_km_ffi.Network
import uniffi.easydoge_km_ffi.PathAddress
import uniffi.easydoge_km_ffi.SignedTransaction
import uniffi.easydoge_km_ffi.SigningEnvelope
import uniffi.easydoge_km_ffi.WifInfo
import uniffi.easydoge_km_ffi.Xpriv
import uniffi.easydoge_km_ffi.Xpub

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

    fun validateMnemonic(
        phrase: String,
        language: Language = Language.ENGLISH,
    ): Boolean = uniffi.easydoge_km_ffi.validateMnemonic(phrase, language)

    fun mnemonicToSeedHex(
        phrase: String,
        passphrase: String? = null,
        language: Language = Language.ENGLISH,
    ): String = uniffi.easydoge_km_ffi.mnemonicToSeedHex(phrase, passphrase, language)

    fun accountKeys(
        phrase: String,
        passphrase: String?,
        language: Language = Language.ENGLISH,
        network: Network = Network.MAINNET,
        account: UInt = 0u,
    ): AccountKeySet =
        uniffi.easydoge_km_ffi.accountXprivFromMnemonic(phrase, passphrase, language, network, account)

    fun derivePathFromXpriv(
        xpriv: Xpriv,
        path: String,
    ): Xpriv = uniffi.easydoge_km_ffi.derivePathFromXpriv(xpriv, path)

    fun derivePathFromXpub(
        xpub: Xpub,
        path: String,
    ): Xpub = uniffi.easydoge_km_ffi.derivePathFromXpub(xpub, path)

    fun xpubFromXpriv(xpriv: Xpriv): Xpub = uniffi.easydoge_km_ffi.xpubFromXpriv(xpriv)

    fun deriveAddressFromXpriv(
        xpriv: Xpriv,
        path: String,
    ): PathAddress = uniffi.easydoge_km_ffi.deriveAddressFromXpriv(xpriv, path)

    fun deriveAddressFromXpub(
        xpub: Xpub,
        path: String,
    ): PathAddress = uniffi.easydoge_km_ffi.deriveAddressFromXpub(xpub, path)

    fun inspectXpriv(xpriv: Xpriv): ExtendedKeyInfo = uniffi.easydoge_km_ffi.inspectXpriv(xpriv)

    fun inspectXpub(xpub: Xpub): ExtendedKeyInfo = uniffi.easydoge_km_ffi.inspectXpub(xpub)

    fun wifFromXpriv(xpriv: Xpriv): String = uniffi.easydoge_km_ffi.wifFromXpriv(xpriv)

    fun addressFromWif(
        network: Network = Network.MAINNET,
        wif: String,
    ): WifInfo = uniffi.easydoge_km_ffi.addressFromWif(network, wif)

    fun validateAddress(
        network: Network = Network.MAINNET,
        address: String,
    ): Boolean = uniffi.easydoge_km_ffi.validateAddress(network, address)

    fun createMultisigDescriptor(
        network: Network = Network.MAINNET,
        threshold: UByte,
        cosignerXpubs: List<Xpub>,
        childPath: String,
        sorted: Boolean = true,
    ): MultisigDescriptor =
        uniffi.easydoge_km_ffi.createMultisigDescriptor(network, threshold, cosignerXpubs, childPath, sorted)

    fun signMessage(
        network: Network = Network.MAINNET,
        wif: String,
        message: String,
    ): MessageSignature = uniffi.easydoge_km_ffi.signMessage(network, wif, message)

    fun verifyMessage(
        network: Network = Network.MAINNET,
        address: String,
        signatureBase64: String,
        message: String,
    ): Boolean = uniffi.easydoge_km_ffi.verifyMessage(network, address, signatureBase64, message)

    fun signP2pkhTransaction(
        network: Network = Network.MAINNET,
        unsignedTxHex: String,
        inputIndex: ULong,
        scriptPubkeyHex: String,
        wif: String,
        sighashType: UInt = 1u,
    ): SignedTransaction =
        uniffi.easydoge_km_ffi.signP2pkhTransaction(
            network,
            unsignedTxHex,
            inputIndex,
            scriptPubkeyHex,
            wif,
            sighashType,
        )

    fun signSigningEnvelope(
        envelope: SigningEnvelope,
        wif: String,
    ): SigningEnvelope = uniffi.easydoge_km_ffi.signSigningEnvelope(envelope, wif)

    fun combineSigningEnvelopes(envelopes: List<SigningEnvelope>): SigningEnvelope =
        uniffi.easydoge_km_ffi.combineSigningEnvelopes(envelopes)

    fun finalizeSigningEnvelope(envelope: SigningEnvelope): SignedTransaction =
        uniffi.easydoge_km_ffi.finalizeSigningEnvelope(envelope)
}
