package io.easydoge.km

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

class WalletProtectionPolicyTest {
    private val sdkLevels = listOf(24, 28, 29, 30, 36)

    @Test
    fun noPromptKeysNeverRequireUserAuthentication() {
        for (sdk in sdkLevels) {
            val policy = WalletProtectionPolicy.keyAuthPolicy(StoredWalletProtection.NoPrompt, sdk)
            assertEquals(WalletKeyAuthenticators.None, policy.authenticators)
            assertFalse(policy.userAuthenticationRequired)
            assertFalse(policy.invalidatedByBiometricEnrollment)
        }
    }

    @Test
    fun biometricKeysAcceptStrongBiometricsOnlyAndAreInvalidatedByNewEnrollment() {
        for (sdk in sdkLevels) {
            val policy = WalletProtectionPolicy.keyAuthPolicy(StoredWalletProtection.Biometric, sdk)
            assertEquals(WalletKeyAuthenticators.BiometricStrong, policy.authenticators)
            assertTrue(policy.userAuthenticationRequired)
            assertTrue(policy.invalidatedByBiometricEnrollment)
        }
    }

    @Test
    fun deviceCredentialKeysAcceptBiometricsOrTheDeviceCredentialFromApi30() {
        for (sdk in listOf(30, 31, 36)) {
            val policy = WalletProtectionPolicy.keyAuthPolicy(StoredWalletProtection.DeviceCredential, sdk)
            assertEquals(WalletKeyAuthenticators.BiometricStrongOrDeviceCredential, policy.authenticators)
            assertTrue(policy.userAuthenticationRequired)
            assertFalse(policy.invalidatedByBiometricEnrollment)
        }
    }

    @Test
    fun deviceCredentialFailsClosedBelowApi30() {
        for (sdk in listOf(0, 24, 28, 29)) {
            val error = assertFailsWith<IllegalStateException> {
                WalletProtectionPolicy.keyAuthPolicy(StoredWalletProtection.DeviceCredential, sdk)
            }
            assertTrue(error.message!!.contains("requires Android 11 (API 30)"))
        }
    }

    @Test
    fun biometricAndDeviceCredentialNeverShareAPolicy() {
        assertTrue(
            WalletProtectionPolicy.keyAuthPolicy(StoredWalletProtection.Biometric, 36) !=
                WalletProtectionPolicy.keyAuthPolicy(StoredWalletProtection.DeviceCredential, 36),
        )
    }

    @Test
    fun exportIsGovernedByTheStoredMode() {
        for (stored in StoredWalletProtection.entries) {
            // Asking for the stored mode, or for no prompt, resolves to the stored mode.
            assertEquals(stored, WalletProtectionPolicy.resolveExportProtection(stored, stored))
            assertEquals(stored, WalletProtectionPolicy.resolveExportProtection(stored, StoredWalletProtection.NoPrompt))
        }
    }

    @Test
    fun exportRejectsARequestedModeThatTheWalletWasNotStoredWith() {
        val mismatches = listOf(
            Triple(StoredWalletProtection.NoPrompt, StoredWalletProtection.Biometric, "biometric"),
            Triple(StoredWalletProtection.NoPrompt, StoredWalletProtection.DeviceCredential, "device-credential"),
            Triple(StoredWalletProtection.Biometric, StoredWalletProtection.DeviceCredential, "device-credential"),
            Triple(StoredWalletProtection.DeviceCredential, StoredWalletProtection.Biometric, "biometric"),
        )
        for ((stored, requested, name) in mismatches) {
            val error = assertFailsWith<IllegalArgumentException> {
                WalletProtectionPolicy.resolveExportProtection(stored, requested)
            }
            assertEquals("Stored wallet is not protected with $name", error.message)
        }
    }

    @Test
    fun promptedModesRequireAnAuthenticator() {
        val authenticator = WalletAuthenticator { cipher, _ -> cipher }
        assertNull(WalletProtectionPolicy.requireAuthenticator(StoredWalletProtection.NoPrompt, null))
        assertNull(WalletProtectionPolicy.requireAuthenticator(StoredWalletProtection.NoPrompt, authenticator))
        for (protection in listOf(StoredWalletProtection.Biometric, StoredWalletProtection.DeviceCredential)) {
            assertSame(authenticator, WalletProtectionPolicy.requireAuthenticator(protection, authenticator))
            val error = assertFailsWith<IllegalStateException> {
                WalletProtectionPolicy.requireAuthenticator(protection, null)
            }
            assertTrue(error.message!!.contains("requires a WalletAuthenticator"))
        }
    }
}
