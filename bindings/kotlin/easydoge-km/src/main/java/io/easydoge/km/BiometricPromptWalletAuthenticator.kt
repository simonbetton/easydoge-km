package io.easydoge.km

import android.app.Activity
import android.os.Build
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import java.util.concurrent.atomic.AtomicBoolean
import javax.crypto.Cipher
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlin.coroutines.suspendCoroutine

/**
 * A [WalletAuthenticator] that shows the AndroidX `BiometricPrompt`, bound to the wallet cipher
 * through `BiometricPrompt.CryptoObject`.
 *
 * [currentActivity] must return the foreground activity, which must be an
 * `androidx.fragment.app.FragmentActivity` (React Native and AppCompat activities are).
 * Never call the store from `runBlocking` on the main thread: the prompt needs the main thread.
 */
class BiometricPromptWalletAuthenticator(
    private val title: String = "Unlock Dogecoin wallet secret",
    private val negativeButtonText: String = "Cancel",
    private val currentActivity: () -> Activity?,
) : WalletAuthenticator {
    override suspend fun authorize(cipher: Cipher, protection: StoredWalletProtection): Cipher {
        val activity = currentActivity() as? FragmentActivity
            ?: throw WalletAuthenticationException(
                "Stored wallet authentication requires a foreground FragmentActivity",
            )
        val promptInfo = promptInfo(protection)
        return suspendCoroutine { continuation ->
            val settled = AtomicBoolean(false)
            activity.runOnUiThread {
                try {
                    check(!activity.isFinishing && !activity.supportFragmentManager.isStateSaved) {
                        "Stored wallet authentication requires a resumed activity"
                    }
                    val callback = object : BiometricPrompt.AuthenticationCallback() {
                        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                            if (!settled.compareAndSet(false, true)) return
                            val authorized = result.cryptoObject?.cipher
                            if (authorized == null) {
                                continuation.resumeWithException(
                                    WalletAuthenticationException("Authentication result did not include the wallet cipher"),
                                )
                            } else {
                                continuation.resume(authorized)
                            }
                        }

                        override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                            if (!settled.compareAndSet(false, true)) return
                            continuation.resumeWithException(
                                WalletAuthenticationException("Stored wallet authentication failed: $errString", errorCode),
                            )
                        }
                        // onAuthenticationFailed (a rejected attempt) is not terminal: the prompt stays open.
                    }
                    BiometricPrompt(activity, ContextCompat.getMainExecutor(activity), callback)
                        .authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
                } catch (error: Exception) {
                    if (settled.compareAndSet(false, true)) {
                        continuation.resumeWithException(error)
                    }
                }
            }
        }
    }

    private fun promptInfo(protection: StoredWalletProtection): BiometricPrompt.PromptInfo {
        val builder = BiometricPrompt.PromptInfo.Builder().setTitle(title)
        when (WalletProtectionPolicy.keyAuthPolicy(protection, Build.VERSION.SDK_INT).authenticators) {
            WalletKeyAuthenticators.BiometricStrong ->
                builder
                    .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                    // Required whenever the device credential is not an allowed authenticator.
                    .setNegativeButtonText(negativeButtonText)
            WalletKeyAuthenticators.BiometricStrongOrDeviceCredential ->
                // A negative button must NOT be set when the device credential is allowed.
                builder.setAllowedAuthenticators(
                    BiometricManager.Authenticators.BIOMETRIC_STRONG or
                        BiometricManager.Authenticators.DEVICE_CREDENTIAL,
                )
            WalletKeyAuthenticators.None ->
                error("Stored wallet protection no-prompt does not use an authenticator")
        }
        return builder.build()
    }
}
