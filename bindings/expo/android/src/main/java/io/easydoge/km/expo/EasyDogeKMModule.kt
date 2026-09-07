package io.easydoge.km.expo

import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import io.easydoge.km.AndroidKeystoreWalletSecretStore
import io.easydoge.km.EasyDogeKM
import io.easydoge.km.StoredWalletHandle
import io.easydoge.km.StoredWalletProtection
import io.easydoge.km.WireCodec
import uniffi.easydoge_km_ffi.AuditedInput
import uniffi.easydoge_km_ffi.ChangeDestination
import uniffi.easydoge_km_ffi.CoinSelectionStrategy
import uniffi.easydoge_km_ffi.ComposeTransactionRequest
import uniffi.easydoge_km_ffi.ComposeTransactionResult
import uniffi.easydoge_km_ffi.FeePolicy
import uniffi.easydoge_km_ffi.Language
import uniffi.easydoge_km_ffi.MnemonicOptions
import uniffi.easydoge_km_ffi.Network
import uniffi.easydoge_km_ffi.SkippedInput
import uniffi.easydoge_km_ffi.SigningEnvelope
import uniffi.easydoge_km_ffi.SigningEnvelopeInput
import uniffi.easydoge_km_ffi.SigningEnvelopeSignature
import uniffi.easydoge_km_ffi.SigningInputKind
import uniffi.easydoge_km_ffi.SpendableUtxo
import uniffi.easydoge_km_ffi.TransactionOptions
import uniffi.easydoge_km_ffi.TransactionOutput
import uniffi.easydoge_km_ffi.TransactionOutputKind
import uniffi.easydoge_km_ffi.UtxoSigner
import uniffi.easydoge_km_ffi.UtxoSignerKind
import uniffi.easydoge_km_ffi.Xpriv
import uniffi.easydoge_km_ffi.Xpub
import uniffi.easydoge_km_ffi.validateAddress
import uniffi.easydoge_km_ffi.validateMnemonic

class EasyDogeKMModule : Module() {
    private val sdk = EasyDogeKM()
    private val store = AndroidKeystoreWalletSecretStore()

    override fun definition() = ModuleDefinition {
        Name("EasyDogeKM")

        AsyncFunction("generateMnemonic") { options: Map<String, Any>? ->
            sdk.generateMnemonic(
                MnemonicOptions(
                    parseLanguage(options?.get("language") as? String),
                    WireCodec.uint16(options?.get("wordCount") ?: 24, "wordCount"),
                ),
            ).toMap()
        }

        AsyncFunction("validateMnemonic") { phrase: String, language: String? ->
            validateMnemonic(phrase, parseLanguage(language))
        }

        AsyncFunction("mnemonicToSeedHex") { phrase: String, passphrase: String?, language: String? ->
            sdk.mnemonicToSeedHex(phrase, passphrase, parseLanguage(language))
        }

        AsyncFunction("accountKeysFromMnemonic") { phrase: String, passphrase: String?, language: String, network: String, account: Double ->
            sdk.accountKeys(phrase, passphrase, parseLanguage(language), parseNetwork(network), WireCodec.uint32(account, "account")).toMap()
        }

        AsyncFunction("deriveAddressFromXpriv") { xpriv: Map<String, Any?>, path: String ->
            uniffi.easydoge_km_ffi.deriveAddressFromXpriv(xpriv.toXpriv(), path).toMap()
        }

        AsyncFunction("deriveAddressFromXpub") { xpub: Map<String, Any?>, path: String ->
            uniffi.easydoge_km_ffi.deriveAddressFromXpub(xpub.toXpub(), path).toMap()
        }

        AsyncFunction("derivePathFromXpriv") { xpriv: Map<String, Any?>, path: String ->
            uniffi.easydoge_km_ffi.derivePathFromXpriv(xpriv.toXpriv(), path).toMap()
        }

        AsyncFunction("derivePathFromXpub") { xpub: Map<String, Any?>, path: String ->
            uniffi.easydoge_km_ffi.derivePathFromXpub(xpub.toXpub(), path).toMap()
        }

        AsyncFunction("xpubFromXpriv") { xpriv: Map<String, Any?> ->
            uniffi.easydoge_km_ffi.xpubFromXpriv(xpriv.toXpriv()).toMap()
        }

        AsyncFunction("wifFromXpriv") { xpriv: Map<String, Any?> ->
            uniffi.easydoge_km_ffi.wifFromXpriv(xpriv.toXpriv())
        }

        AsyncFunction("addressFromWif") { network: String, wif: String ->
            uniffi.easydoge_km_ffi.addressFromWif(parseNetwork(network), wif).toMap()
        }

        AsyncFunction("validateAddress") { network: String, address: String ->
            validateAddress(parseNetwork(network), address)
        }

        AsyncFunction("inspectXpriv") { xpriv: Map<String, Any?> ->
            sdk.inspectXpriv(xpriv.toXpriv()).toMap()
        }

        AsyncFunction("inspectXpub") { xpub: Map<String, Any?> ->
            sdk.inspectXpub(xpub.toXpub()).toMap()
        }

        AsyncFunction("createMultisigDescriptor") { network: String, threshold: Double, cosignerXpubs: List<Map<String, Any?>>, childPath: String, sorted: Boolean ->
            sdk.createMultisigDescriptor(
                parseNetwork(network),
                WireCodec.uint8(threshold, "threshold"),
                cosignerXpubs.map { it.toXpub() },
                childPath,
                sorted,
            ).toMap()
        }

        AsyncFunction("signMessage") { network: String, wif: String, message: String ->
            sdk.signMessage(parseNetwork(network), wif, message).toMap()
        }

        AsyncFunction("verifyMessage") { network: String, address: String, signatureBase64: String, message: String ->
            sdk.verifyMessage(parseNetwork(network), address, signatureBase64, message)
        }

        AsyncFunction("signP2pkhTransaction") { network: String, unsignedTxHex: String, inputIndex: Double, scriptPubkeyHex: String, wif: String, sighashType: Double ->
            sdk.signP2pkhTransaction(
                parseNetwork(network),
                unsignedTxHex,
                WireCodec.uint64(inputIndex, "inputIndex"),
                scriptPubkeyHex,
                wif,
                WireCodec.uint32(sighashType, "sighashType"),
            ).toMap()
        }

        AsyncFunction("signSigningEnvelope") { envelope: Map<String, Any?>, wif: String ->
            sdk.signSigningEnvelope(envelope.toSigningEnvelope(), wif).toMap()
        }

        AsyncFunction("combineSigningEnvelopes") { envelopes: List<Map<String, Any?>> ->
            sdk.combineSigningEnvelopes(envelopes.map { it.toSigningEnvelope() }).toMap()
        }

        AsyncFunction("finalizeSigningEnvelope") { envelope: Map<String, Any?> ->
            sdk.finalizeSigningEnvelope(envelope.toSigningEnvelope()).toMap()
        }

        AsyncFunction("composeAndSignTransaction") { request: Map<String, Any?> ->
            sdk.composeAndSignTransaction(request.toComposeTransactionRequest()).toMap()
        }

        AsyncFunction("storeMnemonic") { phrase: String, protection: String ->
            store.storeMnemonic(phrase, parseProtection(protection)).toMap()
        }

        AsyncFunction("exportMnemonic") { handle: Map<String, String>, protection: String ->
            store.exportMnemonic(StoredWalletHandle(handle["id"] ?: ""), parseProtection(protection))
        }

        AsyncFunction("protectionLevel") { handle: Map<String, String> ->
            when (store.protectionLevel(StoredWalletHandle(handle["id"] ?: ""))) {
                io.easydoge.km.StorageProtectionLevel.HardwareBacked -> "hardware-backed"
                io.easydoge.km.StorageProtectionLevel.OsBacked -> "os-backed"
                io.easydoge.km.StorageProtectionLevel.Unsupported -> "unsupported"
            }
        }
    }
}

private fun parseNetwork(value: String?): Network = when (value) {
    "testnet" -> Network.TESTNET
    "regtest" -> Network.REGTEST
    else -> Network.MAINNET
}

private fun parseLanguage(value: String?): Language = when (value) {
    "simplified-chinese" -> Language.SIMPLIFIED_CHINESE
    "traditional-chinese" -> Language.TRADITIONAL_CHINESE
    "czech" -> Language.CZECH
    "french" -> Language.FRENCH
    "italian" -> Language.ITALIAN
    "japanese" -> Language.JAPANESE
    "korean" -> Language.KOREAN
    "portuguese" -> Language.PORTUGUESE
    "spanish" -> Language.SPANISH
    else -> Language.ENGLISH
}

private fun parseProtection(value: String): StoredWalletProtection = when (value) {
    "device-credential" -> StoredWalletProtection.DeviceCredential
    "biometric" -> StoredWalletProtection.Biometric
    else -> StoredWalletProtection.NoPrompt
}

private fun parseSigningInputKind(value: String?): SigningInputKind = when (value) {
    "p2pkh" -> SigningInputKind.P2PKH
    "p2sh-multisig", "p2shMultisig" -> SigningInputKind.P2SH_MULTISIG
    else -> error("Invalid signing input kind: ${value.orEmpty()}")
}

private fun parseUtxoSignerKind(value: String?): UtxoSignerKind = when (value) {
    "wif" -> UtxoSignerKind.WIF
    "xpriv-derivation", "xprivDerivation" -> UtxoSignerKind.XPRIV_DERIVATION
    else -> error("Invalid UTXO signer kind: ${value.orEmpty()}")
}

private fun parseTransactionOutputKind(value: String?): TransactionOutputKind = when (value) {
    "address" -> TransactionOutputKind.ADDRESS
    "op-return", "opReturn" -> TransactionOutputKind.OP_RETURN
    "expert-raw-script", "expertRawScript" -> TransactionOutputKind.EXPERT_RAW_SCRIPT
    else -> error("Invalid transaction output kind: ${value.orEmpty()}")
}

private fun parseCoinSelectionStrategy(value: String?): CoinSelectionStrategy = when (value) {
    "min-inputs", "minInputs" -> CoinSelectionStrategy.MIN_INPUTS
    "smallest-first", "smallestFirst" -> CoinSelectionStrategy.SMALLEST_FIRST
    "largest-first", "largestFirst" -> CoinSelectionStrategy.LARGEST_FIRST
    "manual-selected-inputs", "manualSelectedInputs" -> CoinSelectionStrategy.MANUAL_SELECTED_INPUTS
    else -> error("Invalid coin selection strategy: ${value.orEmpty()}")
}

private fun StoredWalletHandle.toMap(): Map<String, String> = mapOf("id" to id)
private fun Map<String, Any?>.toXpriv(): Xpriv = Xpriv(parseNetwork(this["network"] as? String), this["encoded"] as? String ?: "")
private fun Map<String, Any?>.toXpub(): Xpub = Xpub(parseNetwork(this["network"] as? String), this["encoded"] as? String ?: "")

private fun uniffi.easydoge_km_ffi.GeneratedMnemonic.toMap(): Map<String, Any> =
    mapOf("phrase" to phrase, "language" to language.raw(), "wordCount" to wordCount.toInt())

private fun uniffi.easydoge_km_ffi.AccountKeySet.toMap(): Map<String, Any> =
    mapOf(
        "network" to network.raw(),
        "account" to account.toInt(),
        "accountPath" to accountPath,
        "xpriv" to xpriv.toMap(),
        "xpub" to xpub.toMap(),
    )

private fun uniffi.easydoge_km_ffi.PathAddress.toMap(): Map<String, Any> =
    mapOf("network" to network.raw(), "path" to path, "publicKeyHex" to publicKeyHex, "address" to address)

private fun Xpriv.toMap(): Map<String, String> = mapOf("network" to network.raw(), "encoded" to encoded)
private fun Xpub.toMap(): Map<String, String> = mapOf("network" to network.raw(), "encoded" to encoded)

private fun uniffi.easydoge_km_ffi.WifInfo.toMap(): Map<String, Any> =
    mapOf(
        "network" to network.raw(),
        "publicKeyHex" to publicKeyHex,
        "address" to address,
        "compressed" to compressed,
    )

private fun uniffi.easydoge_km_ffi.ExtendedKeyInfo.toMap(): Map<String, Any?> =
    mapOf(
        "network" to network.raw(),
        "depth" to depth.toInt(),
        "parentFingerprintHex" to parentFingerprintHex,
        "childNumber" to childNumber.toInt(),
        "publicKeyHex" to publicKeyHex,
        "privateKeyRedacted" to privateKeyRedacted,
    )

private fun uniffi.easydoge_km_ffi.MultisigDescriptor.toMap(): Map<String, Any> =
    mapOf(
        "network" to network.raw(),
        "threshold" to threshold.toInt(),
        "cosignerCount" to cosignerCount.toInt(),
        "childPath" to childPath,
        "sorted" to sorted,
        "publicKeysHex" to publicKeysHex,
        "redeemScriptHex" to redeemScriptHex,
        "p2shAddress" to p2shAddress,
    )

private fun uniffi.easydoge_km_ffi.MessageSignature.toMap(): Map<String, Any> =
    mapOf(
        "network" to network.raw(),
        "address" to address,
        "signatureBase64" to signatureBase64,
    )

private fun uniffi.easydoge_km_ffi.SignedTransaction.toMap(): Map<String, Any> =
    mapOf(
        "network" to network.raw(),
        "signedTxHex" to signedTxHex,
    )

@Suppress("UNCHECKED_CAST")
private fun Map<String, Any?>.toSigningEnvelope(): SigningEnvelope =
    SigningEnvelope(
        version = WireCodec.uint8(this["version"] ?: 1, "version"),
        network = parseNetwork(this["network"] as? String),
        unsignedTxHex = this["unsignedTxHex"] as? String ?: "",
        inputs = (this["inputs"] as? List<Map<String, Any?>>).orEmpty().map { it.toSigningEnvelopeInput() },
        signatures = (this["signatures"] as? List<Map<String, Any?>>).orEmpty().map { it.toSigningEnvelopeSignature() },
    )

private fun Map<String, Any?>.toSigningEnvelopeInput(): SigningEnvelopeInput =
    SigningEnvelopeInput(
        inputIndex = WireCodec.uint64(this["inputIndex"], "inputIndex"),
        kind = parseSigningInputKind(this["kind"] as? String),
        scriptPubkeyHex = this["scriptPubkeyHex"] as? String ?: "",
        redeemScriptHex = this["redeemScriptHex"] as? String,
        sighashType = WireCodec.uint32(this["sighashType"] ?: 1, "sighashType"),
        previousOutputValueKoinu = WireCodec.optionalKoinu(this["previousOutputValueKoinu"], "previousOutputValueKoinu"),
        multisigThreshold = WireCodec.optionalUInt8(this["multisigThreshold"], "multisigThreshold"),
        multisigPublicKeysHex = stringList("multisigPublicKeysHex"),
    )

private fun Map<String, Any?>.toSigningEnvelopeSignature(): SigningEnvelopeSignature =
    SigningEnvelopeSignature(
        inputIndex = WireCodec.uint64(this["inputIndex"], "inputIndex"),
        publicKeyHex = this["publicKeyHex"] as? String ?: "",
        signatureHex = this["signatureHex"] as? String ?: "",
    )

private fun SigningEnvelope.toMap(): Map<String, Any> =
    mapOf(
        "version" to version.toInt(),
        "network" to network.raw(),
        "unsignedTxHex" to unsignedTxHex,
        "inputs" to inputs.map { it.toMap() },
        "signatures" to signatures.map { it.toMap() },
    )

private fun SigningEnvelopeInput.toMap(): Map<String, Any?> =
    mapOf(
        "inputIndex" to WireCodec.safeInteger(inputIndex, "inputIndex"),
        "kind" to kind.raw(),
        "scriptPubkeyHex" to scriptPubkeyHex,
        "redeemScriptHex" to redeemScriptHex,
        "sighashType" to sighashType.toInt(),
        "previousOutputValueKoinu" to previousOutputValueKoinu?.let { WireCodec.koinuString(it) },
        "multisigThreshold" to multisigThreshold?.toInt(),
        "multisigPublicKeysHex" to multisigPublicKeysHex,
    )

private fun SigningEnvelopeSignature.toMap(): Map<String, Any> =
    mapOf(
        "inputIndex" to WireCodec.safeInteger(inputIndex, "inputIndex"),
        "publicKeyHex" to publicKeyHex,
        "signatureHex" to signatureHex,
    )

private fun ComposeTransactionResult.toMap(): Map<String, Any?> =
    mapOf(
        "network" to network.raw(),
        "selectedInputs" to selectedInputs.map { it.toMap() },
        "skippedInputs" to skippedInputs.map { it.toMap() },
        "inputTotalKoinu" to WireCodec.koinuString(inputTotalKoinu),
        "spendOutputTotalKoinu" to WireCodec.koinuString(spendOutputTotalKoinu),
        "changeAmountKoinu" to WireCodec.koinuString(changeAmountKoinu),
        "changeAddress" to changeAddress,
        "changeScriptPubkeyHex" to changeScriptPubkeyHex,
        "feeKoinu" to WireCodec.koinuString(feeKoinu),
        "estimatedSizeBytes" to WireCodec.safeInteger(estimatedSizeBytes, "estimatedSizeBytes"),
        "actualSizeBytes" to actualSizeBytes?.let { WireCodec.safeInteger(it, "actualSizeBytes") },
        "dustChangeFoldedIntoFee" to dustChangeFoldedIntoFee,
        "unsignedTxHex" to unsignedTxHex,
        "signedTxHex" to signedTxHex,
        "signingEnvelope" to signingEnvelope?.toMap(),
    )

private fun AuditedInput.toMap(): Map<String, Any> =
    mapOf(
        "txid" to txid,
        "vout" to vout.toLong(),
        "previousOutputValueKoinu" to WireCodec.koinuString(previousOutputValueKoinu),
        "scriptPubkeyHex" to scriptPubkeyHex,
        "kind" to kind.raw(),
    )

private fun SkippedInput.toMap(): Map<String, Any> =
    mapOf(
        "txid" to txid,
        "vout" to vout.toLong(),
        "previousOutputValueKoinu" to WireCodec.koinuString(previousOutputValueKoinu),
        "reason" to reason,
    )

@Suppress("UNCHECKED_CAST")
private fun Map<String, Any?>.dictionary(key: String): Map<String, Any?> =
    this[key] as? Map<String, Any?> ?: emptyMap()

@Suppress("UNCHECKED_CAST")
private fun Map<String, Any?>.dictionaries(key: String): List<Map<String, Any?>> =
    this[key] as? List<Map<String, Any?>> ?: emptyList()

private fun Map<String, Any?>.stringList(key: String): List<String> =
    (this[key] as? List<*>).orEmpty().filterIsInstance<String>()

private fun Map<String, Any?>.toComposeTransactionRequest(): ComposeTransactionRequest =
    ComposeTransactionRequest(
        network = parseNetwork(this["network"] as? String),
        utxos = dictionaries("utxos").map { it.toSpendableUtxo() },
        outputs = dictionaries("outputs").map { it.toTransactionOutput() },
        feePolicy = dictionary("feePolicy").toFeePolicy(),
        coinSelection = parseCoinSelectionStrategy(this["coinSelection"] as? String),
        change = (this["change"] as? Map<*, *>)?.let { dictionary("change").toChangeDestination() },
        options = dictionary("options").toTransactionOptions(),
    )

private fun Map<String, Any?>.toSpendableUtxo(): SpendableUtxo =
    SpendableUtxo(
        txid = this["txid"] as? String ?: "",
        vout = WireCodec.uint32(this["vout"], "vout"),
        previousOutputValueKoinu = WireCodec.koinu(this["previousOutputValueKoinu"], "previousOutputValueKoinu"),
        scriptPubkeyHex = this["scriptPubkeyHex"] as? String ?: "",
        kind = parseSigningInputKind(this["kind"] as? String),
        redeemScriptHex = this["redeemScriptHex"] as? String,
        multisigThreshold = WireCodec.optionalUInt8(this["multisigThreshold"], "multisigThreshold"),
        multisigPublicKeysHex = stringList("multisigPublicKeysHex"),
        signers = dictionaries("signers").map { it.toUtxoSigner() },
        manuallySelected = this["manuallySelected"] as? Boolean ?: false,
    )

private fun Map<String, Any?>.toUtxoSigner(): UtxoSigner =
    UtxoSigner(
        kind = parseUtxoSignerKind(this["kind"] as? String),
        wif = this["wif"] as? String,
        xpriv = (this["xpriv"] as? Map<*, *>)?.let { dictionary("xpriv").toXpriv() },
        derivationPath = this["derivationPath"] as? String,
    )

private fun Map<String, Any?>.toTransactionOutput(): TransactionOutput =
    TransactionOutput(
        kind = parseTransactionOutputKind(this["kind"] as? String),
        valueKoinu = WireCodec.koinu(this["valueKoinu"], "valueKoinu"),
        address = this["address"] as? String,
        opReturnDataHex = this["opReturnDataHex"] as? String,
        scriptHex = this["scriptHex"] as? String,
    )

private fun Map<String, Any?>.toFeePolicy(): FeePolicy =
    FeePolicy(
        feeRateKoinuPerKb = WireCodec.koinu(this["feeRateKoinuPerKb"], "feeRateKoinuPerKb"),
        dustThresholdKoinu = WireCodec.koinu(this["dustThresholdKoinu"], "dustThresholdKoinu"),
    )

private fun Map<String, Any?>.toChangeDestination(): ChangeDestination =
    ChangeDestination(
        address = this["address"] as? String,
        xpriv = (this["xpriv"] as? Map<*, *>)?.let { dictionary("xpriv").toXpriv() },
        derivationPath = this["derivationPath"] as? String,
    )

private fun Map<String, Any?>.toTransactionOptions(): TransactionOptions =
    TransactionOptions(
        version = WireCodec.int32(this["version"] ?: 1, "version"),
        lockTime = WireCodec.uint32(this["lockTime"] ?: 0, "lockTime"),
        sequence = WireCodec.uint32(this["sequence"] ?: 4294967295.0, "sequence"),
        sighashType = WireCodec.uint32(this["sighashType"] ?: 1, "sighashType"),
    )

private fun Network.raw(): String = when (this) {
    Network.MAINNET -> "mainnet"
    Network.TESTNET -> "testnet"
    Network.REGTEST -> "regtest"
}

private fun Language.raw(): String = when (this) {
    Language.ENGLISH -> "english"
    Language.SIMPLIFIED_CHINESE -> "simplified-chinese"
    Language.TRADITIONAL_CHINESE -> "traditional-chinese"
    Language.CZECH -> "czech"
    Language.FRENCH -> "french"
    Language.ITALIAN -> "italian"
    Language.JAPANESE -> "japanese"
    Language.KOREAN -> "korean"
    Language.PORTUGUESE -> "portuguese"
    Language.SPANISH -> "spanish"
}

private fun SigningInputKind.raw(): String = when (this) {
    SigningInputKind.P2PKH -> "p2pkh"
    SigningInputKind.P2SH_MULTISIG -> "p2sh-multisig"
}
