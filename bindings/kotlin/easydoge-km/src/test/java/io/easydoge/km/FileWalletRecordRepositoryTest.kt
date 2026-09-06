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
