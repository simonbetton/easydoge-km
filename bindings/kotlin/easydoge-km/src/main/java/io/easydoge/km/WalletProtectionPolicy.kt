package io.easydoge.km

/** Which authenticators may authorize one use of a stored wallet key. */
enum class WalletKeyAuthenticators {
    /** The key is usable without user authentication. */
    None,

    /** Class 3 (strong) biometrics only. */
    BiometricStrong,

    /** Class 3 (strong) biometrics, or the device PIN, pattern, or password. */
    BiometricStrongOrDeviceCredential,
}

/** The Android Keystore key-use policy for one [StoredWalletProtection] mode. */
data class WalletKeyAuthPolicy(
    val authenticators: WalletKeyAuthenticators,
    val invalidatedByBiometricEnrollment: Boolean,
) {
    /** True when every use of the key needs a fresh user authentication. */
    val userAuthenticationRequired: Boolean
        get() = authenticators != WalletKeyAuthenticators.None
}

/** Pure decisions about stored wallet protection. No Android framework calls, so it is unit-tested on the JVM. */
object WalletProtectionPolicy {
    /** Android 11. Below this, a Keystore operation cannot be authorized by the device credential through a prompt. */
    const val DEVICE_CREDENTIAL_MIN_SDK: Int = 30

    /** The key policy for [protection] on a device running API level [sdkInt]. Fails closed when unsupported. */
    fun keyAuthPolicy(protection: StoredWalletProtection, sdkInt: Int): WalletKeyAuthPolicy =
        when (protection) {
            StoredWalletProtection.NoPrompt ->
                WalletKeyAuthPolicy(WalletKeyAuthenticators.None, invalidatedByBiometricEnrollment = false)
            StoredWalletProtection.Biometric ->
                WalletKeyAuthPolicy(WalletKeyAuthenticators.BiometricStrong, invalidatedByBiometricEnrollment = true)
            StoredWalletProtection.DeviceCredential -> {
                check(sdkInt >= DEVICE_CREDENTIAL_MIN_SDK) {
                    "Device-credential protection requires Android 11 (API 30) or newer"
                }
                WalletKeyAuthPolicy(
                    WalletKeyAuthenticators.BiometricStrongOrDeviceCredential,
                    invalidatedByBiometricEnrollment = false,
                )
            }
        }

    /**
     * The protection mode that governs an export. The mode chosen at storage time always wins;
     * a caller that asks for a different prompted mode is rejected instead of being ignored.
     */
    fun resolveExportProtection(
        stored: StoredWalletProtection,
        requested: StoredWalletProtection,
    ): StoredWalletProtection {
        require(requested == StoredWalletProtection.NoPrompt || requested == stored) {
            "Stored wallet is not protected with ${wireName(requested)}"
        }
        return stored
    }

    /** The authenticator to use for [protection], or null when no prompt is needed. Fails closed when one is needed but absent. */
    fun requireAuthenticator(
        protection: StoredWalletProtection,
        authenticator: WalletAuthenticator?,
    ): WalletAuthenticator? {
        if (protection == StoredWalletProtection.NoPrompt) return null
        return checkNotNull(authenticator) {
            "Stored wallet protection ${wireName(protection)} requires a WalletAuthenticator"
        }
    }

    private fun wireName(protection: StoredWalletProtection): String =
        when (protection) {
            StoredWalletProtection.NoPrompt -> "no-prompt"
            StoredWalletProtection.DeviceCredential -> "device-credential"
            StoredWalletProtection.Biometric -> "biometric"
        }
}
