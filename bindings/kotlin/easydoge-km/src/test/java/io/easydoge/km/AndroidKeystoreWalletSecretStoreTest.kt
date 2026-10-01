package io.easydoge.km

import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import kotlin.coroutines.Continuation
import kotlin.coroutines.EmptyCoroutineContext
import kotlin.coroutines.startCoroutine
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Exercises the store's authentication flow on the JVM with a software key vault and a fake
 * authenticator. Android Keystore and BiometricPrompt themselves cannot run here.
 */
class AndroidKeystoreWalletSecretStoreTest {
    private val mnemonic =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    private val repository = RecordingRepository()
    private val vault = SoftwareKeyVault()

    private fun store(authenticator: WalletAuthenticator?, sdkInt: Int = 36) =
        AndroidKeystoreWalletSecretStore(repository, authenticator, vault, sdkInt)

    @Test
    fun noPromptWalletsRoundTripWithoutAnAuthenticator() {
        val store = store(authenticator = null)
        val handle = runSuspend { store.storeMnemonic(mnemonic, StoredWalletProtection.NoPrompt) }
        assertEquals(StoredWalletProtection.NoPrompt, repository.records.getValue(handle.id).protection)
        assertEquals(WalletKeyAuthenticators.None, vault.policies.values.single().authenticators)
        assertEquals(mnemonic, runSuspend { store.exportMnemonic(handle, StoredWalletProtection.NoPrompt) })
    }

    @Test
    fun noPromptWalletsNeverInvokeTheAuthenticator() {
        val authenticator = RecordingAuthenticator()
        val store = store(authenticator)
        val handle = runSuspend { store.storeMnemonic(mnemonic, StoredWalletProtection.NoPrompt) }
        runSuspend { store.exportMnemonic(handle, StoredWalletProtection.NoPrompt) }
        assertTrue(authenticator.requests.isEmpty())
    }

    @Test
    fun biometricWalletsAuthenticateOnStoreAndOnExport() {
        val authenticator = RecordingAuthenticator()
        val store = store(authenticator)
        val handle = runSuspend { store.storeMnemonic(mnemonic, StoredWalletProtection.Biometric) }
        assertEquals(listOf(StoredWalletProtection.Biometric), authenticator.requests)
        assertEquals(StoredWalletProtection.Biometric, repository.records.getValue(handle.id).protection)
        assertEquals(
            WalletKeyAuthPolicy(WalletKeyAuthenticators.BiometricStrong, invalidatedByBiometricEnrollment = true),
            vault.policies.values.single(),
        )
        assertEquals(mnemonic, runSuspend { store.exportMnemonic(handle, StoredWalletProtection.Biometric) })
        assertEquals(List(2) { StoredWalletProtection.Biometric }, authenticator.requests)
    }

    @Test
    fun deviceCredentialWalletsUseTheirOwnKeyPolicy() {
        val authenticator = RecordingAuthenticator()
        val store = store(authenticator, sdkInt = 30)
        runSuspend { store.storeMnemonic(mnemonic, StoredWalletProtection.DeviceCredential) }
        assertEquals(listOf(StoredWalletProtection.DeviceCredential), authenticator.requests)
        assertEquals(
            WalletKeyAuthPolicy(
                WalletKeyAuthenticators.BiometricStrongOrDeviceCredential,
                invalidatedByBiometricEnrollment = false,
            ),
            vault.policies.values.single(),
        )
    }

    @Test
    fun exportingAProtectedWalletWithNoPromptStillAuthenticatesWithTheStoredMode() {
        val authenticator = RecordingAuthenticator()
        val store = store(authenticator)
        val handle = runSuspend { store.storeMnemonic(mnemonic, StoredWalletProtection.DeviceCredential) }
        assertEquals(mnemonic, runSuspend { store.exportMnemonic(handle, StoredWalletProtection.NoPrompt) })
        assertEquals(List(2) { StoredWalletProtection.DeviceCredential }, authenticator.requests)
    }

    @Test
    fun exportRejectsARequestedModeThatDiffersFromTheStoredMode() {
        val authenticator = RecordingAuthenticator()
        val store = store(authenticator)
        val biometric = runSuspend { store.storeMnemonic(mnemonic, StoredWalletProtection.Biometric) }
        val unprotected = runSuspend { store.storeMnemonic(mnemonic, StoredWalletProtection.NoPrompt) }
        authenticator.requests.clear()

        val wrongMode = assertFailsWith<IllegalArgumentException> {
            runSuspend { store.exportMnemonic(biometric, StoredWalletProtection.DeviceCredential) }
        }
        assertEquals("Stored wallet is not protected with device-credential", wrongMode.message)
        val notProtected = assertFailsWith<IllegalArgumentException> {
            runSuspend { store.exportMnemonic(unprotected, StoredWalletProtection.Biometric) }
        }
        assertEquals("Stored wallet is not protected with biometric", notProtected.message)
        assertTrue(authenticator.requests.isEmpty())
    }

    @Test
    fun protectedModesFailClosedWithoutAnAuthenticator() {
        val error = assertFailsWith<IllegalStateException> {
            runSuspend { store(authenticator = null).storeMnemonic(mnemonic, StoredWalletProtection.Biometric) }
        }
        assertTrue(error.message!!.contains("requires a WalletAuthenticator"))
        assertTrue(vault.keys.isEmpty() && vault.policies.isEmpty() && repository.records.isEmpty())

        val handle = runSuspend { store(RecordingAuthenticator()).storeMnemonic(mnemonic, StoredWalletProtection.Biometric) }
        val exportError = assertFailsWith<IllegalStateException> {
            runSuspend { store(authenticator = null).exportMnemonic(handle, StoredWalletProtection.NoPrompt) }
        }
        assertTrue(exportError.message!!.contains("requires a WalletAuthenticator"))
    }

    @Test
    fun deviceCredentialFailsClosedBelowApi30BeforeCreatingAKey() {
        val authenticator = RecordingAuthenticator()
        val error = assertFailsWith<IllegalStateException> {
            runSuspend { store(authenticator, sdkInt = 29).storeMnemonic(mnemonic, StoredWalletProtection.DeviceCredential) }
        }
        assertTrue(error.message!!.contains("requires Android 11 (API 30)"))
        assertTrue(vault.policies.isEmpty() && repository.records.isEmpty() && authenticator.requests.isEmpty())
    }

    @Test
    fun aFailedAuthenticationAtStoreTimeDeletesTheKeyAndSavesNoRecord() {
        val store = store(RecordingAuthenticator(failure = WalletAuthenticationException("canceled", 10)))
        val error = assertFailsWith<WalletAuthenticationException> {
            runSuspend { store.storeMnemonic(mnemonic, StoredWalletProtection.Biometric) }
        }
        assertEquals(10, error.errorCode)
        assertEquals(1, vault.deleted.size)
        assertTrue(vault.keys.isEmpty() && repository.records.isEmpty())
    }

    @Test
    fun aFailedAuthenticationAtExportTimeReturnsNoMnemonic() {
        val handle = runSuspend { store(RecordingAuthenticator()).storeMnemonic(mnemonic, StoredWalletProtection.Biometric) }
        val failing = store(RecordingAuthenticator(failure = WalletAuthenticationException("canceled", 10)))
        assertFailsWith<WalletAuthenticationException> {
            runSuspend { failing.exportMnemonic(handle, StoredWalletProtection.Biometric) }
        }
        // The key and record are untouched, so a later successful authentication still works.
        assertEquals(
            mnemonic,
            runSuspend { store(RecordingAuthenticator()).exportMnemonic(handle, StoredWalletProtection.Biometric) },
        )
    }

    @Test
    fun recordsWrittenBeforeTheModeWasPersistedExportWithoutAPrompt() {
        val handle = runSuspend { store(authenticator = null).storeMnemonic(mnemonic, StoredWalletProtection.NoPrompt) }
        val legacyText = StoredWalletRecordCodec.encode(repository.records.getValue(handle.id))
            .lines().filterNot { it.startsWith("mode=") }.joinToString("\n")
        repository.save(StoredWalletRecordCodec.decode(legacyText))
        assertEquals(mnemonic, runSuspend { store(authenticator = null).exportMnemonic(handle, StoredWalletProtection.NoPrompt) })
    }

    @Test
    fun thePublicFactoryFailsClosedBeforeTouchingAndroidKeystore() {
        // No authenticator: a Keystore call would surface as a provider error, not this message.
        val error = assertFailsWith<IllegalStateException> {
            runSuspend { AndroidKeystoreWalletSecretStore.inMemory().storeMnemonic(mnemonic, StoredWalletProtection.Biometric) }
        }
        assertTrue(error.message!!.contains("requires a WalletAuthenticator"))
    }

    /** Runs a suspend block that never actually suspends (all fakes here complete synchronously). */
    private fun <T> runSuspend(block: suspend () -> T): T {
        var outcome: Result<T>? = null
        block.startCoroutine(Continuation(EmptyCoroutineContext) { outcome = it })
        return (outcome ?: error("The suspend block did not complete synchronously")).getOrThrow()
    }

    private class RecordingAuthenticator(private val failure: Exception? = null) : WalletAuthenticator {
        val requests = mutableListOf<StoredWalletProtection>()

        override suspend fun authorize(cipher: Cipher, protection: StoredWalletProtection): Cipher {
            requests += protection
            failure?.let { throw it }
            return cipher
        }
    }

    private class RecordingRepository : WalletRecordRepository {
        val records = mutableMapOf<String, StoredWalletRecord>()

        override fun load(id: String): StoredWalletRecord? = records[id]

        override fun save(record: StoredWalletRecord) {
            records[record.handle.id] = record
        }

        override fun delete(id: String) {
            records.remove(id)
        }
    }

    /** AES-GCM with ordinary JVM keys. It records the policy it was asked to enforce but cannot enforce it. */
    private class SoftwareKeyVault : WalletKeyVault {
        val keys = mutableMapOf<String, SecretKey>()
        val policies = mutableMapOf<String, WalletKeyAuthPolicy>()
        val deleted = mutableListOf<String>()

        override fun createKey(alias: String, policy: WalletKeyAuthPolicy): StorageProtectionLevel {
            keys[alias] = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
            policies[alias] = policy
            return StorageProtectionLevel.OsBacked
        }

        override fun encryptCipher(alias: String): Cipher =
            Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, keys.getValue(alias)) }

        override fun decryptCipher(alias: String, iv: ByteArray): Cipher =
            Cipher.getInstance("AES/GCM/NoPadding").apply {
                init(Cipher.DECRYPT_MODE, keys.getValue(alias), GCMParameterSpec(128, iv))
            }

        override fun deleteKey(alias: String) {
            keys.remove(alias)
            policies.remove(alias)
            deleted += alias
        }
    }
}
