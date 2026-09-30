package io.easydoge.km

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class StoredWalletRecordCodecTest {
    private val record = StoredWalletRecord(
        handle = StoredWalletHandle("123e4567-e89b-42d3-a456-426614174000"),
        ciphertext = byteArrayOf(0, 1, 2, 0xff.toByte()),
        iv = ByteArray(12) { it.toByte() },
        protectionLevel = StorageProtectionLevel.HardwareBacked,
        protection = StoredWalletProtection.Biometric,
    )

    @Test
    fun roundTripsRecords() {
        val decoded = StoredWalletRecordCodec.decode(StoredWalletRecordCodec.encode(record))
        assertEquals(record.handle, decoded.handle)
        assertContentEquals(record.ciphertext, decoded.ciphertext)
        assertContentEquals(record.iv, decoded.iv)
        assertEquals(record.protectionLevel, decoded.protectionLevel)
        assertEquals(record.protection, decoded.protection)
    }

    @Test
    fun roundTripsEveryProtectionMode() {
        for (mode in StoredWalletProtection.entries) {
            val encoded = StoredWalletRecordCodec.encode(record.copy(protection = mode))
            assertTrue(encoded.lines().contains("mode=${mode.name}"))
            assertEquals(mode, StoredWalletRecordCodec.decode(encoded).protection)
        }
    }

    @Test
    fun recordsWithoutAModeLineDecodeAsNoPrompt() {
        val legacy = StoredWalletRecordCodec.encode(record).lines().filterNot { it.startsWith("mode=") }.joinToString("\n")
        val decoded = StoredWalletRecordCodec.decode(legacy)
        assertEquals(StoredWalletProtection.NoPrompt, decoded.protection)
        assertEquals(record.protectionLevel, decoded.protectionLevel)
        assertContentEquals(record.ciphertext, decoded.ciphertext)
    }

    @Test
    fun rejectsAnUnknownProtectionMode() {
        val unknown = StoredWalletRecordCodec.encode(record).replace("mode=Biometric", "mode=Retina")
        val error = assertFailsWith<IllegalStateException> { StoredWalletRecordCodec.decode(unknown) }
        assertEquals("Stored wallet record has an unknown protection mode", error.message)
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
