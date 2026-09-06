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
