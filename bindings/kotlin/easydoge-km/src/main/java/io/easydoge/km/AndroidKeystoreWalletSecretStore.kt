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
    private val repository: MutableMap<String, StoredWalletRecord> = mutableMapOf(),
) : WalletSecretStore {
    override suspend fun storeMnemonic(
        mnemonic: String,
        protection: StoredWalletProtection,
    ): StoredWalletHandle {
        val id = java.util.UUID.randomUUID().toString()
        val alias = alias(id)
        val protectionLevel = createKey(alias, protection)
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, key(alias))
        val ciphertext = cipher.doFinal(mnemonic.encodeToByteArray())
        val handle = StoredWalletHandle(id)
        repository[id] = StoredWalletRecord(handle, ciphertext, cipher.iv, protectionLevel)
        return handle
    }

    override suspend fun exportMnemonic(
        handle: StoredWalletHandle,
        protection: StoredWalletProtection,
    ): String {
        val record = repository[handle.id] ?: error("Stored wallet handle not found")
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, key(alias(handle.id)), GCMParameterSpec(128, record.iv))
        return cipher.doFinal(record.ciphertext).decodeToString()
    }

    override suspend fun protectionLevel(handle: StoredWalletHandle): StorageProtectionLevel =
        repository[handle.id]?.protectionLevel ?: StorageProtectionLevel.Unsupported

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

    private fun key(alias: String): SecretKey {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        return keyStore.getKey(alias, null) as SecretKey
    }

    private fun alias(id: String): String = "io.easydoge.km.wallet.$id"

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
    }
}

