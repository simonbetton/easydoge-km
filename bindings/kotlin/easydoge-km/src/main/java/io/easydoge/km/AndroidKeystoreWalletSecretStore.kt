package io.easydoge.km

import android.os.Build

data class StoredWalletRecord(
    val handle: StoredWalletHandle,
    val ciphertext: ByteArray,
    val iv: ByteArray,
    val protectionLevel: StorageProtectionLevel,
    /** The protection mode chosen at storage time. It selects the prompt; the Keystore key enforces it. */
    val protection: StoredWalletProtection,
)

class AndroidKeystoreWalletSecretStore internal constructor(
    private val repository: WalletRecordRepository,
    private val authenticator: WalletAuthenticator?,
    private val vault: WalletKeyVault,
    private val sdkInt: Int,
) : WalletSecretStore {
    /**
     * [authenticator] shows the user-authentication prompt. It is required for the
     * `DeviceCredential` and `Biometric` modes; without it only `NoPrompt` wallets work.
     */
    constructor(
        repository: WalletRecordRepository,
        authenticator: WalletAuthenticator? = null,
    ) : this(repository, authenticator, AndroidKeystoreKeyVault(), Build.VERSION.SDK_INT)

    override suspend fun storeMnemonic(
        mnemonic: String,
        protection: StoredWalletProtection,
    ): StoredWalletHandle {
        // Both checks fail closed before any key is created.
        val policy = WalletProtectionPolicy.keyAuthPolicy(protection, sdkInt)
        val prompt = WalletProtectionPolicy.requireAuthenticator(protection, authenticator)
        val id = java.util.UUID.randomUUID().toString()
        val alias = alias(id)
        val protectionLevel = vault.createKey(alias, policy)
        try {
            var cipher = vault.encryptCipher(alias)
            if (prompt != null) {
                cipher = prompt.authorize(cipher, protection)
            }
            val ciphertext = cipher.doFinal(mnemonic.encodeToByteArray())
            val record = StoredWalletRecord(StoredWalletHandle(id), ciphertext, cipher.iv, protectionLevel, protection)
            repository.save(record)
            return record.handle
        } catch (error: Exception) {
            vault.deleteKey(alias)
            throw error
        }
    }

    override suspend fun exportMnemonic(
        handle: StoredWalletHandle,
        protection: StoredWalletProtection,
    ): String {
        val record = repository.load(handle.id) ?: error("Stored wallet handle not found")
        val stored = WalletProtectionPolicy.resolveExportProtection(record.protection, protection)
        val prompt = WalletProtectionPolicy.requireAuthenticator(stored, authenticator)
        var cipher = vault.decryptCipher(alias(handle.id), record.iv)
        if (prompt != null) {
            cipher = prompt.authorize(cipher, stored)
        }
        return cipher.doFinal(record.ciphertext).decodeToString()
    }

    override suspend fun protectionLevel(handle: StoredWalletHandle): StorageProtectionLevel =
        repository.load(handle.id)?.protectionLevel ?: StorageProtectionLevel.Unsupported

    private fun alias(id: String): String = "io.easydoge.km.wallet.$id"

    companion object {
        /** Records persist in app-private, no-backup storage. Use this in apps. */
        fun persistent(
            context: android.content.Context,
            authenticator: WalletAuthenticator? = null,
        ): AndroidKeystoreWalletSecretStore =
            AndroidKeystoreWalletSecretStore(FileWalletRecordRepository.fromContext(context), authenticator)

        /** Records live only for the current process. Tests and demos only. */
        fun inMemory(authenticator: WalletAuthenticator? = null): AndroidKeystoreWalletSecretStore =
            AndroidKeystoreWalletSecretStore(InMemoryWalletRecordRepository(), authenticator)
    }
}
