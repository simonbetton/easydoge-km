package io.easydoge.km

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

data class StoredWalletRecord(
    val handle: StoredWalletHandle,
    val ciphertext: ByteArray,
    val iv: ByteArray,
    val protectionLevel: StorageProtectionLevel,
)

class AndroidKeystoreWalletSecretStore(
    private val repository: WalletRecordRepository,
) : WalletSecretStore {
    override suspend fun storeMnemonic(
        mnemonic: String,
        protection: StoredWalletProtection,
    ): StoredWalletHandle {
        val id = java.util.UUID.randomUUID().toString()
        val alias = alias(id)
        val protectionLevel = createKey(alias, protection)
        try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, requireKey(alias))
            val ciphertext = cipher.doFinal(mnemonic.encodeToByteArray())
            val record = StoredWalletRecord(StoredWalletHandle(id), ciphertext, cipher.iv, protectionLevel)
            repository.save(record)
            return record.handle
        } catch (error: Exception) {
            deleteKey(alias)
            throw error
        }
    }

    override suspend fun exportMnemonic(
        handle: StoredWalletHandle,
        protection: StoredWalletProtection,
    ): String {
        val record = repository.load(handle.id) ?: error("Stored wallet handle not found")
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, requireKey(alias(handle.id)), GCMParameterSpec(128, record.iv))
        return cipher.doFinal(record.ciphertext).decodeToString()
    }

    override suspend fun protectionLevel(handle: StoredWalletHandle): StorageProtectionLevel =
        repository.load(handle.id)?.protectionLevel ?: StorageProtectionLevel.Unsupported

    private fun createKey(alias: String, protection: StoredWalletProtection): StorageProtectionLevel {
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        val builder = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setRandomizedEncryptionRequired(true)

        if (protection != StoredWalletProtection.NoPrompt) {
            builder.setUserAuthenticationRequired(true)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                builder.setUserAuthenticationParameters(
                    0,
                    KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL,
                )
            }
        }

        val requestedStrongBox = Build.VERSION.SDK_INT >= Build.VERSION_CODES.P
        if (requestedStrongBox) {
            try {
                builder.setIsStrongBoxBacked(true)
                generator.init(builder.build())
                generator.generateKey()
                return StorageProtectionLevel.HardwareBacked
            } catch (_: Exception) {
                // Fall through to standard Android Keystore.
            }
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            builder.setIsStrongBoxBacked(false)
        }
        generator.init(builder.build())
        generator.generateKey()
        return StorageProtectionLevel.OsBacked
    }

    private fun requireKey(alias: String): SecretKey =
        keyStore().getKey(alias, null) as? SecretKey
            ?: error("Stored wallet key is missing or was invalidated")

    private fun deleteKey(alias: String) {
        runCatching { keyStore().deleteEntry(alias) }
    }

    private fun keyStore(): KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    private fun alias(id: String): String = "io.easydoge.km.wallet.$id"

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"

        /** Records persist in app-private, no-backup storage. Use this in apps. */
        fun persistent(context: android.content.Context): AndroidKeystoreWalletSecretStore =
            AndroidKeystoreWalletSecretStore(FileWalletRecordRepository.fromContext(context))

        /** Records live only for the current process. Tests and demos only. */
        fun inMemory(): AndroidKeystoreWalletSecretStore =
            AndroidKeystoreWalletSecretStore(InMemoryWalletRecordRepository())
    }
}

