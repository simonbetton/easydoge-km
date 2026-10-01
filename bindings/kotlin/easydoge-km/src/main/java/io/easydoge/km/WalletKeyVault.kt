package io.easydoge.km

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** Creates and uses the per-wallet AES-GCM keys. Production code uses [AndroidKeystoreKeyVault]; unit tests use a software fake. */
internal interface WalletKeyVault {
    /** Creates a new key under [alias] that enforces [policy], and reports where it lives. */
    fun createKey(alias: String, policy: WalletKeyAuthPolicy): StorageProtectionLevel

    /** A cipher initialized to encrypt with the key under [alias]. */
    fun encryptCipher(alias: String): Cipher

    /** A cipher initialized to decrypt with the key under [alias] and [iv]. */
    fun decryptCipher(alias: String, iv: ByteArray): Cipher

    fun deleteKey(alias: String)
}

/** Android Keystore implementation. It cannot run in JVM unit tests. */
internal class AndroidKeystoreKeyVault : WalletKeyVault {
    override fun createKey(alias: String, policy: WalletKeyAuthPolicy): StorageProtectionLevel {
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        val builder = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setRandomizedEncryptionRequired(true)

        if (policy.userAuthenticationRequired) {
            builder.setUserAuthenticationRequired(true)
            builder.setInvalidatedByBiometricEnrollment(policy.invalidatedByBiometricEnrollment)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                // Timeout 0: the user must authenticate for every single use of the key.
                builder.setUserAuthenticationParameters(0, keystoreAuthTypes(policy.authenticators))
            }
            // API 24-29: nothing more to set. The platform default (validity duration -1) already
            // means "authenticate for every use, biometric only", which is the Biometric policy.
            // WalletProtectionPolicy rejects DeviceCredential below API 30 before this is reached.
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

    override fun encryptCipher(alias: String): Cipher =
        initCipher { cipher -> cipher.init(Cipher.ENCRYPT_MODE, requireKey(alias)) }

    override fun decryptCipher(alias: String, iv: ByteArray): Cipher =
        initCipher { cipher -> cipher.init(Cipher.DECRYPT_MODE, requireKey(alias), GCMParameterSpec(128, iv)) }

    override fun deleteKey(alias: String) {
        runCatching { keyStore().deleteEntry(alias) }
    }

    private fun initCipher(init: (Cipher) -> Unit): Cipher {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        try {
            init(cipher)
        } catch (error: KeyPermanentlyInvalidatedException) {
            throw IllegalStateException(
                "Stored wallet key was permanently invalidated by a biometric enrollment or lock screen change",
                error,
            )
        }
        return cipher
    }

    private fun keystoreAuthTypes(authenticators: WalletKeyAuthenticators): Int =
        when (authenticators) {
            WalletKeyAuthenticators.None -> 0
            WalletKeyAuthenticators.BiometricStrong -> KeyProperties.AUTH_BIOMETRIC_STRONG
            WalletKeyAuthenticators.BiometricStrongOrDeviceCredential ->
                KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL
        }

    private fun requireKey(alias: String): SecretKey =
        keyStore().getKey(alias, null) as? SecretKey
            ?: error("Stored wallet key is missing or was invalidated")

    private fun keyStore(): KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    private companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
    }
}
