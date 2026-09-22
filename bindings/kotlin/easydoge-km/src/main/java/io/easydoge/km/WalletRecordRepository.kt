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
