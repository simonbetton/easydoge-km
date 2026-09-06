# Plan 005: Persist Android stored-wallet records so handles survive process death

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md` — unless a reviewer dispatched you and told you they
> maintain the index.
>
> **Drift check (run first)**:
> `git diff --stat 32f1e4d..HEAD -- bindings/kotlin/easydoge-km/src bindings/expo/android docs/SECURITY_MODEL.md CHANGELOG.md`
> If any in-scope file changed since this plan was written, compare the
> "Current state" excerpts against the live code before proceeding; on a
> mismatch, treat it as a STOP condition. (Plan 004 also adds files under
> `bindings/kotlin/easydoge-km/src` and edits the Expo Android module —
> additive changes there are expected.)

## Status

- **Priority**: P1
- **Effort**: M
- **Risk**: MED (Kotlin constructor signature changes; Keystore behavior itself is untouched)
- **Depends on**: none
- **Category**: bug (data loss)
- **Planned at**: commit `32f1e4d`, 2026-09-04
- **Audit finding**: #4 (deep audit, evidence originally collected at `04e7499`, revalidated at `32f1e4d`)

## Why this matters

`AndroidKeystoreWalletSecretStore` encrypts the mnemonic with an Android
Keystore key and then keeps the ciphertext and IV in an in-memory `MutableMap`.
The Keystore key is durable, the ciphertext is not: after process death (which
Android performs routinely) `exportMnemonic` fails with "Stored wallet handle
not found" and the seed phrase is unrecoverable unless the user kept their own
backup. The Expo Android module constructs this store with the default
in-memory map, so every Expo app on Android is affected. The iOS store writes
to the Keychain and is durable. After this plan, records are persisted to
app-private, no-backup storage via a small repository abstraction that is unit
tested on the JVM, and the Expo module uses the persistent variant.

## Current state

- `bindings/kotlin/easydoge-km/src/main/java/io/easydoge/km/AndroidKeystoreWalletSecretStore.kt` — the store (102 lines). `StoredWalletRecord` data class (lines 12–17); constructor `AndroidKeystoreWalletSecretStore(private val repository: MutableMap<String, StoredWalletRecord> = mutableMapOf())` (19–21); `storeMnemonic` writes `repository[id] = StoredWalletRecord(...)` (33); `exportMnemonic` reads `repository[handle.id]` (41); `protectionLevel` reads the record (47–48); `key(alias)` does `keyStore.getKey(alias, null) as SecretKey` (90–93, throws a cast error if the key is gone).
- `bindings/kotlin/easydoge-km/src/main/java/io/easydoge/km/EasyDogeKM.kt` — `StoredWalletHandle`, `StoredWalletProtection`, `StorageProtectionLevel`, `WalletSecretStore` interface (lines 20–46). The interface has no delete method; adding one is out of scope.
- `bindings/kotlin/easydoge-km/build.gradle.kts` — Android library, `minSdk = 24`, `compileSdk = 36`, test deps `kotlin("test")` + JUnit 4. Unit tests run on the JVM with Android stubs, so **Android framework classes (`android.util.Base64`, `SharedPreferences`, Keystore) cannot be exercised in unit tests**; everything testable must be pure Kotlin/JVM.
- `bindings/kotlin/easydoge-km/src/test/java/io/easydoge/km/EasyDogeKMTest.kt` — test style: `kotlin.test.Test`, `assertEquals`, `assertTrue`. Pure-Kotlin tests do not need the native library override in its `companion object`.
- `bindings/expo/android/src/main/java/io/easydoge/km/expo/EasyDogeKMModule.kt` — `private val store = AndroidKeystoreWalletSecretStore()` (line 36) inside an `expo.modules.kotlin.modules.Module`. Expo's `Module` exposes `appContext` whose `reactContext: Context?` gives the Android `Context`.
- `bindings/swift/Sources/EasyDogeKM/KeychainWalletSecretStore.swift` — the iOS counterpart; durable via Keychain. Not touched.
- `docs/SECURITY_MODEL.md` "Storage Boundaries": "Kotlin uses Android Keystore-backed encryption."

Excerpt, `AndroidKeystoreWalletSecretStore.kt:19-45` (today):

```kotlin
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
```

Design decisions (made by the advisor):

- Persist to **files under `Context.noBackupFilesDir`** (`<app>/no_backup/easydoge-km-wallets/<id>.record`). Keystore keys never leave the device, so a cloud-restored ciphertext would be undecryptable; excluding it from Auto Backup avoids confusing "restored but unusable" records. File-based storage is app-private by default and, unlike `SharedPreferences`, can be unit tested with a temp directory on the JVM.
- **Atomic writes**: write `<id>.record.tmp`, `fsync`, then `renameTo` the final name.
- **Text format** (one record per file, hex not Base64 because `java.util.Base64` needs API 26 and `android.util.Base64` is not available on the JVM):

  ```
  easydoge-km-wallet-record/1
  id=<uuid>
  protection=<HardwareBacked|OsBacked|Unsupported>
  iv=<hex>
  ciphertext=<hex>
  ```

- **Handle ids are validated** as UUIDs before being used in a path, because ids arrive from JavaScript through the Expo module.
- The no-arg constructor is removed. Callers choose `AndroidKeystoreWalletSecretStore.persistent(context)` or `AndroidKeystoreWalletSecretStore.inMemory()` explicitly; silently defaulting to in-memory is the bug.

Conventions: 4-space Kotlin, `error("…")` for failures (existing style), `CONTRIBUTING.md` requires tests and doc updates; `scripts/check-open-source-ready.sh` fails on the uppercase "to do"/"fix me" marker words anywhere in the repo, so never write them. `CONTEXT.md` term: "Stored Wallet Handle — an opaque reference to wallet secret material managed by a platform storage adapter."

## Commands you will need

| Purpose | Command | Expected on success |
|---------|---------|---------------------|
| Build native lib (needed by the existing Kotlin parity test) | `cargo build -p easydoge-km-ffi` | exit 0 |
| Kotlin tests | `cd bindings/kotlin && ./gradlew test` | BUILD SUCCESSFUL |
| One test class | `cd bindings/kotlin && ./gradlew :easydoge-km:testDebugUnitTest --tests 'io.easydoge.km.FileWalletRecordRepositoryTest'` | BUILD SUCCESSFUL |
| Compile only | `cd bindings/kotlin && ./gradlew :easydoge-km:compileDebugKotlin` | BUILD SUCCESSFUL |
| Readiness | `bash scripts/check-open-source-ready.sh` | exit 0 |
| Full suite | `./scripts/verify.sh` | exit 0 |

(`./gradlew` needs JDK 17 and an Android SDK; the Gradle wrapper is pinned to 8.13.)

## Scope

**In scope** (the only files you should modify or create):

- `bindings/kotlin/easydoge-km/src/main/java/io/easydoge/km/AndroidKeystoreWalletSecretStore.kt`
- `bindings/kotlin/easydoge-km/src/main/java/io/easydoge/km/WalletRecordRepository.kt` (create)
- `bindings/kotlin/easydoge-km/src/main/java/io/easydoge/km/StoredWalletRecordCodec.kt` (create)
- `bindings/kotlin/easydoge-km/src/test/java/io/easydoge/km/StoredWalletRecordCodecTest.kt` (create)
- `bindings/kotlin/easydoge-km/src/test/java/io/easydoge/km/FileWalletRecordRepositoryTest.kt` (create)
- `bindings/expo/android/src/main/java/io/easydoge/km/expo/EasyDogeKMModule.kt` (line 36 only)
- `docs/SECURITY_MODEL.md`, `CHANGELOG.md`

**Out of scope** (do NOT touch):

- `WalletSecretStore` interface and the Swift/iOS store — no delete/rotate API in this plan (direction candidate for later).
- Biometric/device-credential prompt binding and export protection (finding 8).
- Keystore key parameters in `createKey` (unchanged).
- Expo iOS module, TypeScript types.
- Adding Robolectric or instrumentation tests.

## Git workflow

- Branch: `fix/android-durable-wallet-records`
- Conventional Commits, e.g. `fix(android): persist stored wallet records across process death`
- Do NOT push or open a PR unless the operator instructed it.

## Steps

### Step 1: Record codec, test-first

Create `bindings/kotlin/easydoge-km/src/test/java/io/easydoge/km/StoredWalletRecordCodecTest.kt`:

```kotlin
package io.easydoge.km

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class StoredWalletRecordCodecTest {
    private val record = StoredWalletRecord(
        handle = StoredWalletHandle("123e4567-e89b-42d3-a456-426614174000"),
        ciphertext = byteArrayOf(0, 1, 2, 0xff.toByte()),
        iv = ByteArray(12) { it.toByte() },
        protectionLevel = StorageProtectionLevel.HardwareBacked,
    )

    @Test
    fun roundTripsRecords() {
        val decoded = StoredWalletRecordCodec.decode(StoredWalletRecordCodec.encode(record))
        assertEquals(record.handle, decoded.handle)
        assertContentEquals(record.ciphertext, decoded.ciphertext)
        assertContentEquals(record.iv, decoded.iv)
        assertEquals(record.protectionLevel, decoded.protectionLevel)
    }

    @Test
    fun rejectsUnknownHeaderAndMissingFields() {
        assertFailsWith<IllegalStateException> { StoredWalletRecordCodec.decode("something-else/1\n") }
        val missingIv = StoredWalletRecordCodec.encode(record).lines().filterNot { it.startsWith("iv=") }.joinToString("\n")
        assertFailsWith<IllegalStateException> { StoredWalletRecordCodec.decode(missingIv) }
        assertFailsWith<IllegalStateException> {
            StoredWalletRecordCodec.decode(StoredWalletRecordCodec.encode(record).replace("ciphertext=", "ciphertext=zz"))
        }
    }

    @Test
    fun validatesHandleIds() {
        StoredWalletRecordCodec.requireValidId("123e4567-e89b-42d3-a456-426614174000")
        for (bad in listOf("", "../x", "123e4567-e89b-42d3-a456-426614174000/..", "not-a-uuid")) {
            assertFailsWith<IllegalArgumentException> { StoredWalletRecordCodec.requireValidId(bad) }
        }
    }
}
```

Create `bindings/kotlin/easydoge-km/src/main/java/io/easydoge/km/StoredWalletRecordCodec.kt`:

```kotlin
package io.easydoge.km

/** Serializes [StoredWalletRecord]s to a small line-based text format (version 1). */
object StoredWalletRecordCodec {
    private const val HEADER = "easydoge-km-wallet-record/1"
    private val UUID_PATTERN =
        Regex("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")

    fun requireValidId(id: String) {
        require(UUID_PATTERN.matches(id)) { "Invalid stored wallet handle" }
    }

    fun encode(record: StoredWalletRecord): String {
        requireValidId(record.handle.id)
        return listOf(
            HEADER,
            "id=${record.handle.id}",
            "protection=${record.protectionLevel.name}",
            "iv=${hex(record.iv)}",
            "ciphertext=${hex(record.ciphertext)}",
        ).joinToString("\n", postfix = "\n")
    }

    fun decode(text: String): StoredWalletRecord {
        val lines = text.lines().filter { it.isNotEmpty() }
        check(lines.firstOrNull() == HEADER) { "Unsupported stored wallet record format" }
        val fields = lines.drop(1).associate { line ->
            val separator = line.indexOf('=')
            check(separator > 0) { "Malformed stored wallet record" }
            line.substring(0, separator) to line.substring(separator + 1)
        }
        val id = fields["id"] ?: error("Stored wallet record is missing id")
        requireValidId(id)
        val protection = fields["protection"]?.let { name ->
            StorageProtectionLevel.entries.firstOrNull { it.name == name }
        } ?: error("Stored wallet record has an unknown protection level")
        return StoredWalletRecord(
            handle = StoredWalletHandle(id),
            ciphertext = unhex(fields["ciphertext"] ?: error("Stored wallet record is missing ciphertext")),
            iv = unhex(fields["iv"] ?: error("Stored wallet record is missing iv")),
            protectionLevel = protection,
        )
    }

    private fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }

    private fun unhex(text: String): ByteArray {
        check(text.length % 2 == 0 && text.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) {
            "Stored wallet record contains invalid hex"
        }
        return ByteArray(text.length / 2) { index ->
            text.substring(index * 2, index * 2 + 2).toInt(16).toByte()
        }
    }
}
```

(`StorageProtectionLevel.entries` requires Kotlin 1.9+; the project uses Kotlin 2.4.0.)

**Verify**: `cd bindings/kotlin && ./gradlew :easydoge-km:testDebugUnitTest --tests 'io.easydoge.km.StoredWalletRecordCodecTest'` → BUILD SUCCESSFUL, 3 tests.

### Step 2: Repository abstraction, test-first

Create `bindings/kotlin/easydoge-km/src/test/java/io/easydoge/km/FileWalletRecordRepositoryTest.kt`:

```kotlin
package io.easydoge.km

import java.io.File
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull

class FileWalletRecordRepositoryTest {
    private val directory: File = Files.createTempDirectory("easydoge-km-records").toFile()
    private val id = "123e4567-e89b-42d3-a456-426614174000"
    private val record = StoredWalletRecord(
        handle = StoredWalletHandle(id),
        ciphertext = byteArrayOf(9, 8, 7),
        iv = ByteArray(12) { 1 },
        protectionLevel = StorageProtectionLevel.OsBacked,
    )

    @Test
    fun savedRecordsSurviveANewRepositoryInstance() {
        FileWalletRecordRepository(directory).save(record)
        // A fresh instance simulates a new process reading the same directory.
        val loaded = FileWalletRecordRepository(directory).load(id)!!
        assertEquals(record.handle, loaded.handle)
        assertContentEquals(record.ciphertext, loaded.ciphertext)
        assertContentEquals(record.iv, loaded.iv)
        assertEquals(record.protectionLevel, loaded.protectionLevel)
        assertEquals(listOf("$id.record"), directory.list()!!.toList())
    }

    @Test
    fun missingAndDeletedRecordsLoadAsNull() {
        val repository = FileWalletRecordRepository(directory)
        assertNull(repository.load(id))
        repository.save(record)
        repository.delete(id)
        assertNull(repository.load(id))
    }

    @Test
    fun overwritingKeepsTheLatestRecordOnly() {
        val repository = FileWalletRecordRepository(directory)
        repository.save(record)
        repository.save(record.copy(ciphertext = byteArrayOf(1)))
        assertContentEquals(byteArrayOf(1), repository.load(id)!!.ciphertext)
        assertEquals(1, directory.list()!!.size)
    }

    @Test
    fun rejectsPathLikeHandleIds() {
        val repository = FileWalletRecordRepository(directory)
        assertFailsWith<IllegalArgumentException> { repository.load("../escape") }
        assertFailsWith<IllegalArgumentException> { repository.delete("not-a-uuid") }
    }

    @Test
    fun corruptedFilesFailLoudly() {
        File(directory, "$id.record").writeText("garbage\n")
        assertFailsWith<IllegalStateException> { FileWalletRecordRepository(directory).load(id) }
    }

    @Test
    fun inMemoryRepositoryHasTheSameContract() {
        val repository = InMemoryWalletRecordRepository()
        assertNull(repository.load(id))
        repository.save(record)
        assertEquals(record.handle, repository.load(id)!!.handle)
        repository.delete(id)
        assertNull(repository.load(id))
    }
}
```

Create `bindings/kotlin/easydoge-km/src/main/java/io/easydoge/km/WalletRecordRepository.kt`:

```kotlin
package io.easydoge.km

import android.content.Context
import java.io.File
import java.io.FileOutputStream

/** Durable storage for encrypted [StoredWalletRecord]s, keyed by handle id. */
interface WalletRecordRepository {
    fun load(id: String): StoredWalletRecord?

    fun save(record: StoredWalletRecord)

    fun delete(id: String)
}

/** Process-local storage; records vanish when the process dies. Use only for tests. */
class InMemoryWalletRecordRepository : WalletRecordRepository {
    private val records = mutableMapOf<String, StoredWalletRecord>()

    override fun load(id: String): StoredWalletRecord? = records[id]

    override fun save(record: StoredWalletRecord) {
        records[record.handle.id] = record
    }

    override fun delete(id: String) {
        records.remove(id)
    }
}

/**
 * One file per record inside [directory]. Writes are atomic (temp file + rename).
 * Use [fromContext] in apps so records live in app-private, no-backup storage.
 */
class FileWalletRecordRepository(private val directory: File) : WalletRecordRepository {
    override fun load(id: String): StoredWalletRecord? {
        val file = recordFile(id)
        if (!file.isFile) return null
        return StoredWalletRecordCodec.decode(file.readText())
    }

    override fun save(record: StoredWalletRecord) {
        check(directory.isDirectory || directory.mkdirs()) { "Could not create stored wallet directory" }
        val target = recordFile(record.handle.id)
        val temp = File(directory, "${target.name}.tmp")
        FileOutputStream(temp).use { stream ->
            stream.write(StoredWalletRecordCodec.encode(record).toByteArray(Charsets.UTF_8))
            stream.fd.sync()
        }
        if (!temp.renameTo(target)) {
            temp.delete()
            error("Could not persist stored wallet record")
        }
    }

    override fun delete(id: String) {
        recordFile(id).delete()
    }

    private fun recordFile(id: String): File {
        StoredWalletRecordCodec.requireValidId(id)
        return File(directory, "$id.record")
    }

    companion object {
        fun fromContext(context: Context): FileWalletRecordRepository =
            FileWalletRecordRepository(File(context.noBackupFilesDir, "easydoge-km-wallets"))
    }
}
```

`Context.noBackupFilesDir` exists since API 21 (`minSdk` is 24). The `Context` import compiles against the Android stub jar in unit tests; only `fromContext` touches it and no unit test calls it.

**Verify**: `cd bindings/kotlin && ./gradlew :easydoge-km:testDebugUnitTest --tests 'io.easydoge.km.FileWalletRecordRepositoryTest'` → BUILD SUCCESSFUL, 6 tests.

### Step 3: Switch the store to the repository and clean up orphaned keys

Edit `AndroidKeystoreWalletSecretStore.kt`:

```kotlin
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

    // createKey(...) unchanged

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
```

Keep `StoredWalletRecord` in this file (the codec and repository reference it).

**Verify**: `cd bindings/kotlin && ./gradlew :easydoge-km:compileDebugKotlin` → BUILD SUCCESSFUL. `grep -n "MutableMap<String, StoredWalletRecord>" bindings/kotlin/easydoge-km/src/main/java/io/easydoge/km/AndroidKeystoreWalletSecretStore.kt` → no matches.

### Step 4: Use the persistent store from the Expo Android module

In `bindings/expo/android/src/main/java/io/easydoge/km/expo/EasyDogeKMModule.kt`, replace line 36 (`private val store = AndroidKeystoreWalletSecretStore()`) with:

```kotlin
    private val store by lazy {
        AndroidKeystoreWalletSecretStore.persistent(
            requireNotNull(appContext.reactContext) { "EasyDogeKM stored wallets require an Android context" },
        )
    }
```

`lazy` matters: `appContext` is not available while the module object is being constructed.

**Verify**: `grep -n "AndroidKeystoreWalletSecretStore.persistent\|by lazy" bindings/expo/android/src/main/java/io/easydoge/km/expo/EasyDogeKMModule.kt` → both present; `grep -n "AndroidKeystoreWalletSecretStore()" …EasyDogeKMModule.kt` → no matches. (The Expo module is not compiled by CI — finding 15 — so also re-read the edit for balanced parentheses.)

### Step 5: Documentation

- `docs/SECURITY_MODEL.md`, "Storage Boundaries" bullet for Kotlin → "Kotlin uses Android Keystore-backed encryption; the Keystore-wrapped ciphertext is persisted in app-private, no-backup storage (`Context.noBackupFilesDir`) so Stored Wallet Handles survive process death. Keystore keys never leave the device, so records are intentionally excluded from Auto Backup."
- `CHANGELOG.md`:
  - `### Fixed` (create the heading under `## [Unreleased]` if absent): "Android stored-wallet records (ciphertext and IV) are now persisted to app-private no-backup storage. Previously they lived only in process memory, so a `StoredWalletHandle` became unusable after the process was killed while the Keystore key lingered."
  - `### Changed`: "**Breaking (Kotlin)**: `AndroidKeystoreWalletSecretStore` no longer has a no-argument constructor. Use `AndroidKeystoreWalletSecretStore.persistent(context)` in apps or `.inMemory()` in tests. The Expo Android module now uses the persistent variant."

**Verify**: `bash scripts/check-open-source-ready.sh` → exit 0.

### Step 6: Full verification and manual device check

**Verify (automated)**: `cargo build -p easydoge-km-ffi && (cd bindings/kotlin && ./gradlew test)` → BUILD SUCCESSFUL with `EasyDogeKMTest`, `StoredWalletRecordCodecTest`, `FileWalletRecordRepositoryTest` all passing; then `./scripts/verify.sh` → exit 0.

**Verify (manual, only if an Android device/emulator with an Expo dev client is available; otherwise record "not run" in the report)**: from JavaScript call `storeMnemonic(phrase, "no-prompt")`, keep the returned handle, run `adb shell am force-stop <applicationId>`, relaunch, and call `exportMnemonic(handle, "no-prompt")` → returns the same phrase. Before this plan the second call throws "Stored wallet handle not found".

## Test plan

- `StoredWalletRecordCodecTest`: round trip, unknown header / missing fields / bad hex rejected, handle id validation.
- `FileWalletRecordRepositoryTest`: persistence across repository instances (process-restart simulation), missing/deleted → null, overwrite keeps latest and leaves no temp file, path-like ids rejected, corrupted file fails loudly, in-memory repository contract.
- Existing `EasyDogeKMTest` keeps passing (it does not touch the store).
- Keystore-dependent behavior (`storeMnemonic` / `exportMnemonic`) cannot run on the JVM; covered by the manual device check and by keeping `createKey`/cipher code byte-for-byte unchanged.

## Done criteria

Machine-checkable. ALL must hold:

- [ ] `(cd bindings/kotlin && ./gradlew test)` exits 0; `find bindings/kotlin/easydoge-km/build/test-results -name 'TEST-io.easydoge.km.FileWalletRecordRepositoryTest.xml' | xargs grep -l 'failures="0"'` → one file; same for `StoredWalletRecordCodecTest`
- [ ] `grep -rn "MutableMap<String, StoredWalletRecord>\|AndroidKeystoreWalletSecretStore()" bindings/` → no matches
- [ ] `grep -n "noBackupFilesDir" bindings/kotlin/easydoge-km/src/main/java/io/easydoge/km/WalletRecordRepository.kt docs/SECURITY_MODEL.md` → ≥ 1 match in each
- [ ] `grep -n "persistent(" bindings/expo/android/src/main/java/io/easydoge/km/expo/EasyDogeKMModule.kt` → 1 match
- [ ] `grep -n "process" CHANGELOG.md` → mentions process death under `### Fixed`
- [ ] `./scripts/verify.sh` exits 0
- [ ] `git status --porcelain` lists only in-scope files
- [ ] `plans/README.md` status row updated

## STOP conditions

Stop and report back (do not improvise) if:

- The "Current state" excerpts do not match the live code.
- `./gradlew test` cannot run (no JDK 17 / Android SDK) — report, do not skip.
- The Android stub jar makes `import android.content.Context` fail to compile in the library's unit-test source set (it should not; the main source set is compiled against `android.jar`).
- The installed `expo-modules-core` does not expose `appContext.reactContext` (check a host app's `node_modules/expo-modules-core/android/src/main/java/expo/modules/kotlin/AppContext.kt`); do not guess an alternative accessor.
- You find the `WalletSecretStore` interface must change to make the tests pass.

## Maintenance notes

- Handle deletion and key rotation (`deleteWallet(handle)`) are the natural next API; implement them on `WalletSecretStore` for both platforms together and have the Android version call `repository.delete` plus `deleteKey`.
- If a record exists but the Keystore key was invalidated (biometric enrollment change with `setInvalidatedByBiometricEnrollment`), `exportMnemonic` now fails with "Stored wallet key is missing or was invalidated"; finding 8 should surface that as a typed error to JavaScript.
- Bump the codec `HEADER` version and add a migration branch in `decode` if the record format ever changes; never silently reinterpret old files.
- Reviewer focus: the try/catch in `storeMnemonic` must delete the Keystore alias on any failure after `createKey`, and `save` must never leave a `.tmp` file behind on success.
