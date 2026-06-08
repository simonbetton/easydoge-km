package io.easydoge.km

import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import org.junit.BeforeClass
import uniffi.easydoge_km_ffi.Network
import uniffi.easydoge_km_ffi.SigningEnvelope
import uniffi.easydoge_km_ffi.SigningEnvelopeInput
import uniffi.easydoge_km_ffi.SigningInputKind
import uniffi.easydoge_km_ffi.Xpub

class EasyDogeKMTest {
    @Test
    fun wrapperSurfaceMatchesParityVectors() {
        val vectors = parityVectors()
        val sdk = EasyDogeKM()
        val phrase = string(vectors, "mnemonic.phrase")

        assertTrue(sdk.validateMnemonic(phrase))

        val keys = sdk.accountKeys(
            phrase = phrase,
            passphrase = string(vectors, "mnemonic.passphrase"),
        )
        assertEquals(string(vectors, "mnemonic.account.xpriv"), keys.xpriv.encoded)
        assertEquals(string(vectors, "mnemonic.account.xpub"), keys.xpub.encoded)

        val address = sdk.deriveAddressFromXpub(keys.xpub, string(vectors, "mnemonic.receive.relative_path"))
        assertEquals(string(vectors, "mnemonic.receive.address"), address.address)

        val info = sdk.inspectXpriv(keys.xpriv)
        assertTrue(info.privateKeyRedacted)
        assertEquals(string(vectors, "mnemonic.account.public_key_hex"), info.publicKeyHex)

        val wif = sdk.wifFromXpriv(keys.xpriv)
        assertEquals(string(vectors, "mnemonic.account.wif"), wif)
        assertEquals(string(vectors, "mnemonic.account.address"), sdk.addressFromWif(wif = wif).address)

        val signature = sdk.signMessage(wif = wif, message = string(vectors, "message.text"))
        assertEquals(string(vectors, "message.signature_base64"), signature.signatureBase64)
        assertTrue(
            sdk.verifyMessage(
                address = signature.address,
                signatureBase64 = signature.signatureBase64,
                message = string(vectors, "message.text"),
            ),
        )

        val signed = sdk.signP2pkhTransaction(
            unsignedTxHex = string(vectors, "transaction.unsigned_tx_hex"),
            inputIndex = number(vectors, "transaction.input_index").toLong().toULong(),
            scriptPubkeyHex = string(vectors, "transaction.script_pubkey_hex"),
            wif = wif,
            sighashType = number(vectors, "transaction.sighash_type").toLong().toUInt(),
        )
        assertEquals(string(vectors, "transaction.signed_tx_hex"), signed.signedTxHex)

        val envelope = SigningEnvelope(
            version = 1u.toUByte(),
            network = Network.MAINNET,
            unsignedTxHex = string(vectors, "transaction.unsigned_tx_hex"),
            inputs = listOf(
                SigningEnvelopeInput(
                    inputIndex = number(vectors, "transaction.input_index").toLong().toULong(),
                    kind = SigningInputKind.P2PKH,
                    scriptPubkeyHex = string(vectors, "transaction.script_pubkey_hex"),
                    redeemScriptHex = null,
                    sighashType = number(vectors, "transaction.sighash_type").toLong().toUInt(),
                ),
            ),
            signatures = emptyList(),
        )
        val signedEnvelope = sdk.signSigningEnvelope(envelope, wif)
        val combined = sdk.combineSigningEnvelopes(listOf(signedEnvelope, signedEnvelope))
        assertEquals(1, combined.signatures.size)
        assertEquals(
            string(vectors, "transaction.signed_tx_hex"),
            sdk.finalizeSigningEnvelope(combined).signedTxHex,
        )

        val descriptor = sdk.createMultisigDescriptor(
            threshold = number(vectors, "multisig.threshold").toLong().toUByte(),
            cosignerXpubs = stringList(vectors, "multisig.cosigner_xpubs").map {
                Xpub(Network.MAINNET, it)
            },
            childPath = string(vectors, "multisig.child_path"),
        )
        assertEquals(string(vectors, "multisig.p2sh_address"), descriptor.p2shAddress)
        assertEquals(string(vectors, "multisig.redeem_script_hex"), descriptor.redeemScriptHex)
    }

    companion object {
        @JvmStatic
        @BeforeClass
        fun configureNativeLibrary() {
            val library = File(repoRoot(), "target/debug/${System.mapLibraryName("easydoge_km_ffi")}")
                .canonicalFile
            System.setProperty("uniffi.component.easydoge_km_ffi.libraryOverride", library.path)
        }
    }
}

private fun parityVectors(): Map<String, Any?> =
    JsonParser(File(repoRoot(), "test-vectors/parity.json").readText()).parseObject()

private fun repoRoot(): File {
    var current = File("").canonicalFile
    while (true) {
        if (File(current, "test-vectors/parity.json").isFile) {
            return current
        }
        current = current.parentFile ?: error("Could not locate repository root")
    }
}

private fun string(
    values: Map<String, Any?>,
    path: String,
): String = value(values, path) as String

private fun number(
    values: Map<String, Any?>,
    path: String,
): Number = value(values, path) as Number

@Suppress("UNCHECKED_CAST")
private fun stringList(
    values: Map<String, Any?>,
    path: String,
): List<String> = value(values, path) as List<String>

@Suppress("UNCHECKED_CAST")
private fun value(
    values: Map<String, Any?>,
    path: String,
): Any? = path.split(".").fold(values as Any?) { current, key ->
    (current as Map<String, Any?>)[key]
}

private class JsonParser(private val source: String) {
    private var index = 0

    fun parseObject(): Map<String, Any?> {
        skipWhitespace()
        expect('{')
        val result = linkedMapOf<String, Any?>()
        skipWhitespace()
        if (peek() == '}') {
            index += 1
            return result
        }
        while (true) {
            val key = parseString()
            skipWhitespace()
            expect(':')
            result[key] = parseValue()
            skipWhitespace()
            when (peek()) {
                ',' -> {
                    index += 1
                    skipWhitespace()
                }
                '}' -> {
                    index += 1
                    return result
                }
                else -> error("Expected object separator at $index")
            }
        }
    }

    private fun parseArray(): List<Any?> {
        expect('[')
        val result = mutableListOf<Any?>()
        skipWhitespace()
        if (peek() == ']') {
            index += 1
            return result
        }
        while (true) {
            result += parseValue()
            skipWhitespace()
            when (peek()) {
                ',' -> {
                    index += 1
                    skipWhitespace()
                }
                ']' -> {
                    index += 1
                    return result
                }
                else -> error("Expected array separator at $index")
            }
        }
    }

    private fun parseValue(): Any? {
        skipWhitespace()
        return when (peek()) {
            '"' -> parseString()
            '{' -> parseObject()
            '[' -> parseArray()
            't' -> parseLiteral("true", true)
            'f' -> parseLiteral("false", false)
            'n' -> parseLiteral("null", null)
            else -> parseNumber()
        }
    }

    private fun parseString(): String {
        expect('"')
        val result = StringBuilder()
        while (index < source.length) {
            when (val char = source[index++]) {
                '"' -> return result.toString()
                '\\' -> result.append(parseEscape())
                else -> result.append(char)
            }
        }
        error("Unterminated string")
    }

    private fun parseEscape(): Char =
        when (val escaped = source[index++]) {
            '"', '\\', '/' -> escaped
            'b' -> '\b'
            'f' -> '\u000C'
            'n' -> '\n'
            'r' -> '\r'
            't' -> '\t'
            'u' -> {
                val value = source.substring(index, index + 4).toInt(16)
                index += 4
                value.toChar()
            }
            else -> error("Unsupported escape sequence at $index")
        }

    private fun parseNumber(): Number {
        val start = index
        while (index < source.length && source[index] in "-0123456789.eE+") {
            index += 1
        }
        val text = source.substring(start, index)
        return if (text.any { it == '.' || it == 'e' || it == 'E' }) {
            text.toDouble()
        } else {
            text.toLong()
        }
    }

    private fun <T> parseLiteral(
        literal: String,
        value: T,
    ): T {
        check(source.startsWith(literal, index)) { "Expected $literal at $index" }
        index += literal.length
        return value
    }

    private fun expect(expected: Char) {
        skipWhitespace()
        check(peek() == expected) { "Expected $expected at $index" }
        index += 1
    }

    private fun peek(): Char = source.getOrNull(index) ?: error("Unexpected end of JSON")

    private fun skipWhitespace() {
        while (index < source.length && source[index].isWhitespace()) {
            index += 1
        }
    }
}
