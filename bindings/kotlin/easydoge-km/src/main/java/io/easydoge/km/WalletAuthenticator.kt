package io.easydoge.km

import javax.crypto.Cipher

/**
 * Authorizes one use of a stored wallet key by authenticating the user.
 *
 * [authorize] receives a [Cipher] that is already initialized with the Android Keystore key.
 * An implementation must bind that cipher to the authentication UI (for example
 * `BiometricPrompt.CryptoObject`) and return the cipher from the successful result. It must
 * throw when the user cancels or authentication fails; it must never return an unauthorized cipher.
 */
fun interface WalletAuthenticator {
    suspend fun authorize(cipher: Cipher, protection: StoredWalletProtection): Cipher
}

/** User authentication for a stored wallet did not complete. [errorCode] is the platform prompt's code, when there is one. */
class WalletAuthenticationException(message: String, val errorCode: Int? = null) : Exception(message)
