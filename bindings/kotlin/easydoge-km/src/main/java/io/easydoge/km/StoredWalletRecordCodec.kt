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
