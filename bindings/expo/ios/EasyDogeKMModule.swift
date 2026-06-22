import ExpoModulesCore
import EasyDogeKM

public class EasyDogeKMModule: Module {
    private let sdk = EasyDogeKM()
    private let store = KeychainWalletSecretStore()

    public func definition() -> ModuleDefinition {
        Name("EasyDogeKM")

        AsyncFunction("generateMnemonic") { (options: [String: Any]?) in
            let opts = MnemonicOptions(
                language: parseLanguage(options?["language"] as? String),
                wordCount: UInt16(options?["wordCount"] as? Int ?? 24)
            )
            return try sdk.generateMnemonic(options: opts).asDictionary()
        }

        AsyncFunction("validateMnemonic") { (phrase: String, language: String?) in
            try validateMnemonic(phrase: phrase, language: parseLanguage(language))
        }

        AsyncFunction("mnemonicToSeedHex") { (phrase: String, passphrase: String?, language: String?) in
            try mnemonicToSeedHex(phrase: phrase, passphrase: passphrase, language: parseLanguage(language))
        }

        AsyncFunction("accountKeysFromMnemonic") { (phrase: String, passphrase: String?, language: String, network: String, account: Int) in
            try sdk.accountKeys(
                phrase: phrase,
                passphrase: passphrase,
                language: parseLanguage(language),
                network: parseNetwork(network),
                account: UInt32(account)
            ).asDictionary()
        }

        AsyncFunction("deriveAddressFromXpriv") { (xpriv: [String: String], path: String) in
            try deriveAddressFromXpriv(xpriv: Xpriv.fromDictionary(xpriv), path: path).asDictionary()
        }

        AsyncFunction("deriveAddressFromXpub") { (xpub: [String: String], path: String) in
            try deriveAddressFromXpub(xpub: Xpub.fromDictionary(xpub), path: path).asDictionary()
        }

        AsyncFunction("derivePathFromXpriv") { (xpriv: [String: String], path: String) in
            try derivePathFromXpriv(xpriv: Xpriv.fromDictionary(xpriv), path: path).asDictionary()
        }

        AsyncFunction("derivePathFromXpub") { (xpub: [String: String], path: String) in
            try derivePathFromXpub(xpub: Xpub.fromDictionary(xpub), path: path).asDictionary()
        }

        AsyncFunction("xpubFromXpriv") { (xpriv: [String: String]) in
            try xpubFromXpriv(xpriv: Xpriv.fromDictionary(xpriv)).asDictionary()
        }

        AsyncFunction("wifFromXpriv") { (xpriv: [String: String]) in
            try wifFromXpriv(xpriv: Xpriv.fromDictionary(xpriv))
        }

        AsyncFunction("addressFromWif") { (network: String, wif: String) in
            try addressFromWif(network: parseNetwork(network), wif: wif).asDictionary()
        }

        AsyncFunction("validateAddress") { (network: String, address: String) in
            try validateAddress(network: parseNetwork(network), address: address)
        }

        AsyncFunction("inspectXpriv") { (xpriv: [String: String]) in
            try sdk.inspectXpriv(xpriv: Xpriv.fromDictionary(xpriv)).asDictionary()
        }

        AsyncFunction("inspectXpub") { (xpub: [String: String]) in
            try sdk.inspectXpub(xpub: Xpub.fromDictionary(xpub)).asDictionary()
        }

        AsyncFunction("createMultisigDescriptor") { (network: String, threshold: Int, cosignerXpubs: [[String: String]], childPath: String, sorted: Bool) in
            try sdk.createMultisigDescriptor(
                network: parseNetwork(network),
                threshold: UInt8(threshold),
                cosignerXpubs: cosignerXpubs.map { Xpub.fromDictionary($0) },
                childPath: childPath,
                sorted: sorted
            ).asDictionary()
        }

        AsyncFunction("signMessage") { (network: String, wif: String, message: String) in
            try sdk.signMessage(network: parseNetwork(network), wif: wif, message: message).asDictionary()
        }

        AsyncFunction("verifyMessage") { (network: String, address: String, signatureBase64: String, message: String) in
            try sdk.verifyMessage(
                network: parseNetwork(network),
                address: address,
                signatureBase64: signatureBase64,
                message: message
            )
        }

        AsyncFunction("signP2pkhTransaction") { (network: String, unsignedTxHex: String, inputIndex: Int, scriptPubkeyHex: String, wif: String, sighashType: Int) in
            try sdk.signP2pkhTransaction(
                network: parseNetwork(network),
                unsignedTxHex: unsignedTxHex,
                inputIndex: UInt64(inputIndex),
                scriptPubkeyHex: scriptPubkeyHex,
                wif: wif,
                sighashType: UInt32(sighashType)
            ).asDictionary()
        }

        AsyncFunction("signSigningEnvelope") { (envelope: [String: Any], wif: String) in
            try sdk.signSigningEnvelope(envelope: SigningEnvelope.fromDictionary(envelope), wif: wif).asDictionary()
        }

        AsyncFunction("combineSigningEnvelopes") { (envelopes: [[String: Any]]) in
            try sdk.combineSigningEnvelopes(
                envelopes: envelopes.map { try SigningEnvelope.fromDictionary($0) }
            ).asDictionary()
        }

        AsyncFunction("finalizeSigningEnvelope") { (envelope: [String: Any]) in
            try sdk.finalizeSigningEnvelope(envelope: SigningEnvelope.fromDictionary(envelope)).asDictionary()
        }

        AsyncFunction("composeAndSignTransaction") { (request: [String: Any]) in
            try sdk.composeAndSignTransaction(
                request: ComposeTransactionRequest.fromDictionary(request)
            ).asDictionary()
        }

        AsyncFunction("storeMnemonic") { (phrase: String, protection: String) async throws in
            try await store.storeMnemonic(phrase, protection: parseProtection(protection)).asDictionary()
        }

        AsyncFunction("exportMnemonic") { (handle: [String: String], protection: String) async throws in
            try await store.exportMnemonic(
                handle: StoredWalletHandle(id: handle["id"] ?? ""),
                protection: parseProtection(protection)
            )
        }

        AsyncFunction("protectionLevel") { (handle: [String: String]) async throws in
            try await store.protectionLevel(handle: StoredWalletHandle(id: handle["id"] ?? "")).rawValue
        }
    }
}

private enum EasyDogeKMExpoError: LocalizedError {
    case invalidSigningInputKind(String)
    case invalidUtxoSignerKind(String)
    case invalidTransactionOutputKind(String)
    case invalidCoinSelectionStrategy(String)

    var errorDescription: String? {
        switch self {
        case let .invalidSigningInputKind(value):
            return "Invalid signing input kind: \(value)"
        case let .invalidUtxoSignerKind(value):
            return "Invalid UTXO signer kind: \(value)"
        case let .invalidTransactionOutputKind(value):
            return "Invalid transaction output kind: \(value)"
        case let .invalidCoinSelectionStrategy(value):
            return "Invalid coin selection strategy: \(value)"
        }
    }
}

private func parseNetwork(_ value: String?) -> Network {
    switch value {
    case "testnet": return .testnet
    case "regtest": return .regtest
    default: return .mainnet
    }
}

private func parseLanguage(_ value: String?) -> Language {
    switch value {
    case "simplified-chinese": return .simplifiedChinese
    case "traditional-chinese": return .traditionalChinese
    case "czech": return .czech
    case "french": return .french
    case "italian": return .italian
    case "japanese": return .japanese
    case "korean": return .korean
    case "portuguese": return .portuguese
    case "spanish": return .spanish
    default: return .english
    }
}

private func parseProtection(_ value: String) -> StoredWalletProtection {
    switch value {
    case "device-credential": return .deviceCredential
    case "biometric": return .biometric
    default: return .noPrompt
    }
}

private extension StorageProtectionLevel {
    var rawValue: String {
        switch self {
        case .hardwareBacked: return "hardware-backed"
        case .osBacked: return "os-backed"
        case .unsupported: return "unsupported"
        }
    }
}

private extension StoredWalletHandle {
    func asDictionary() -> [String: String] {
        ["id": id]
    }
}

private extension GeneratedMnemonic {
    func asDictionary() -> [String: Any] {
        ["phrase": phrase, "language": language.rawString, "wordCount": Int(wordCount)]
    }
}

private extension AccountKeySet {
    func asDictionary() -> [String: Any] {
        [
            "network": network.rawString,
            "account": Int(account),
            "accountPath": accountPath,
            "xpriv": xpriv.asDictionary(),
            "xpub": xpub.asDictionary()
        ]
    }
}

private extension PathAddress {
    func asDictionary() -> [String: Any] {
        [
            "network": network.rawString,
            "path": path,
            "publicKeyHex": publicKeyHex,
            "address": address
        ]
    }
}

private extension Xpriv {
    static func fromDictionary(_ value: [String: String]) -> Xpriv {
        Xpriv(network: parseNetwork(value["network"]), encoded: value["encoded"] ?? "")
    }

    static func fromDictionary(_ value: [String: Any]) -> Xpriv {
        Xpriv(network: parseNetwork(value["network"] as? String), encoded: value["encoded"] as? String ?? "")
    }

    func asDictionary() -> [String: String] {
        ["network": network.rawString, "encoded": encoded]
    }
}

private extension Xpub {
    static func fromDictionary(_ value: [String: String]) -> Xpub {
        Xpub(network: parseNetwork(value["network"]), encoded: value["encoded"] ?? "")
    }

    static func fromDictionary(_ value: [String: Any]) -> Xpub {
        Xpub(network: parseNetwork(value["network"] as? String), encoded: value["encoded"] as? String ?? "")
    }

    func asDictionary() -> [String: String] {
        ["network": network.rawString, "encoded": encoded]
    }
}

private extension WifInfo {
    func asDictionary() -> [String: Any] {
        [
            "network": network.rawString,
            "publicKeyHex": publicKeyHex,
            "address": address,
            "compressed": compressed
        ]
    }
}

private extension ExtendedKeyInfo {
    func asDictionary() -> [String: Any] {
        var value: [String: Any] = [
            "network": network.rawString,
            "depth": Int(depth),
            "parentFingerprintHex": parentFingerprintHex,
            "childNumber": Int(childNumber),
            "privateKeyRedacted": privateKeyRedacted
        ]
        value["publicKeyHex"] = publicKeyHex
        return value
    }
}

private extension MultisigDescriptor {
    func asDictionary() -> [String: Any] {
        [
            "network": network.rawString,
            "threshold": Int(threshold),
            "cosignerCount": Int(cosignerCount),
            "childPath": childPath,
            "sorted": sorted,
            "publicKeysHex": publicKeysHex,
            "redeemScriptHex": redeemScriptHex,
            "p2shAddress": p2shAddress
        ]
    }
}

private extension MessageSignature {
    func asDictionary() -> [String: Any] {
        [
            "network": network.rawString,
            "address": address,
            "signatureBase64": signatureBase64
        ]
    }
}

private extension SignedTransaction {
    func asDictionary() -> [String: Any] {
        [
            "network": network.rawString,
            "signedTxHex": signedTxHex
        ]
    }
}

private extension SigningEnvelope {
    static func fromDictionary(_ value: [String: Any]) throws -> SigningEnvelope {
        SigningEnvelope(
            version: UInt8(intValue(value["version"], default: 1)),
            network: parseNetwork(value["network"] as? String),
            unsignedTxHex: value["unsignedTxHex"] as? String ?? "",
            inputs: try (value["inputs"] as? [[String: Any]] ?? []).map { try SigningEnvelopeInput.fromDictionary($0) },
            signatures: (value["signatures"] as? [[String: Any]] ?? []).map { SigningEnvelopeSignature.fromDictionary($0) }
        )
    }

    func asDictionary() -> [String: Any] {
        [
            "version": Int(version),
            "network": network.rawString,
            "unsignedTxHex": unsignedTxHex,
            "inputs": inputs.map { $0.asDictionary() },
            "signatures": signatures.map { $0.asDictionary() }
        ]
    }
}

private extension SigningEnvelopeInput {
    static func fromDictionary(_ value: [String: Any]) throws -> SigningEnvelopeInput {
        SigningEnvelopeInput(
            inputIndex: UInt64(intValue(value["inputIndex"], default: 0)),
            kind: try SigningInputKind.fromRawString(value["kind"] as? String),
            scriptPubkeyHex: value["scriptPubkeyHex"] as? String ?? "",
            redeemScriptHex: value["redeemScriptHex"] as? String,
            sighashType: UInt32(intValue(value["sighashType"], default: 1)),
            previousOutputValueKoinu: uint64Optional(value["previousOutputValueKoinu"]),
            multisigThreshold: uint8Optional(value["multisigThreshold"]),
            multisigPublicKeysHex: value["multisigPublicKeysHex"] as? [String] ?? []
        )
    }

    func asDictionary() -> [String: Any] {
        var value: [String: Any] = [
            "inputIndex": Int(inputIndex),
            "kind": kind.rawString,
            "scriptPubkeyHex": scriptPubkeyHex,
            "sighashType": Int(sighashType)
        ]
        value["redeemScriptHex"] = redeemScriptHex
        value["previousOutputValueKoinu"] = previousOutputValueKoinu.map { Int($0) }
        value["multisigThreshold"] = multisigThreshold.map { Int($0) }
        value["multisigPublicKeysHex"] = multisigPublicKeysHex
        return value
    }
}

private extension SigningEnvelopeSignature {
    static func fromDictionary(_ value: [String: Any]) -> SigningEnvelopeSignature {
        SigningEnvelopeSignature(
            inputIndex: UInt64(intValue(value["inputIndex"], default: 0)),
            publicKeyHex: value["publicKeyHex"] as? String ?? "",
            signatureHex: value["signatureHex"] as? String ?? ""
        )
    }

    func asDictionary() -> [String: Any] {
        [
            "inputIndex": Int(inputIndex),
            "publicKeyHex": publicKeyHex,
            "signatureHex": signatureHex
        ]
    }
}

private extension SigningInputKind {
    static func fromRawString(_ value: String?) throws -> SigningInputKind {
        switch value {
        case "p2pkh": return .p2pkh
        case "p2sh-multisig", "p2shMultisig": return .p2shMultisig
        default: throw EasyDogeKMExpoError.invalidSigningInputKind(value ?? "")
        }
    }

    var rawString: String {
        switch self {
        case .p2pkh: return "p2pkh"
        case .p2shMultisig: return "p2sh-multisig"
        }
    }
}

private extension UtxoSignerKind {
    static func fromRawString(_ value: String?) throws -> UtxoSignerKind {
        switch value {
        case "wif": return .wif
        case "xpriv-derivation", "xprivDerivation": return .xprivDerivation
        default: throw EasyDogeKMExpoError.invalidUtxoSignerKind(value ?? "")
        }
    }
}

private extension TransactionOutputKind {
    static func fromRawString(_ value: String?) throws -> TransactionOutputKind {
        switch value {
        case "address": return .address
        case "op-return", "opReturn": return .opReturn
        case "expert-raw-script", "expertRawScript": return .expertRawScript
        default: throw EasyDogeKMExpoError.invalidTransactionOutputKind(value ?? "")
        }
    }
}

private extension CoinSelectionStrategy {
    static func fromRawString(_ value: String?) throws -> CoinSelectionStrategy {
        switch value {
        case "min-inputs", "minInputs": return .minInputs
        case "smallest-first", "smallestFirst": return .smallestFirst
        case "largest-first", "largestFirst": return .largestFirst
        case "manual-selected-inputs", "manualSelectedInputs": return .manualSelectedInputs
        default: throw EasyDogeKMExpoError.invalidCoinSelectionStrategy(value ?? "")
        }
    }
}

private extension ComposeTransactionRequest {
    static func fromDictionary(_ value: [String: Any]) throws -> ComposeTransactionRequest {
        ComposeTransactionRequest(
            network: parseNetwork(value["network"] as? String),
            utxos: try dictionaries(value["utxos"]).map { try SpendableUtxo.fromDictionary($0) },
            outputs: try dictionaries(value["outputs"]).map { try TransactionOutput.fromDictionary($0) },
            feePolicy: FeePolicy.fromDictionary(dictionary(value["feePolicy"])),
            coinSelection: try CoinSelectionStrategy.fromRawString(value["coinSelection"] as? String),
            change: (value["change"] as? [String: Any]).map { ChangeDestination.fromDictionary($0) },
            options: TransactionOptions.fromDictionary(dictionary(value["options"]))
        )
    }
}

private extension SpendableUtxo {
    static func fromDictionary(_ value: [String: Any]) throws -> SpendableUtxo {
        SpendableUtxo(
            txid: value["txid"] as? String ?? "",
            vout: UInt32(intValue(value["vout"], default: 0)),
            previousOutputValueKoinu: uint64Value(value["previousOutputValueKoinu"], default: 0),
            scriptPubkeyHex: value["scriptPubkeyHex"] as? String ?? "",
            kind: try SigningInputKind.fromRawString(value["kind"] as? String),
            redeemScriptHex: value["redeemScriptHex"] as? String,
            multisigThreshold: uint8Optional(value["multisigThreshold"]),
            multisigPublicKeysHex: value["multisigPublicKeysHex"] as? [String] ?? [],
            signers: try dictionaries(value["signers"]).map { try UtxoSigner.fromDictionary($0) },
            manuallySelected: value["manuallySelected"] as? Bool ?? false
        )
    }
}

private extension UtxoSigner {
    static func fromDictionary(_ value: [String: Any]) throws -> UtxoSigner {
        UtxoSigner(
            kind: try UtxoSignerKind.fromRawString(value["kind"] as? String),
            wif: value["wif"] as? String,
            xpriv: (value["xpriv"] as? [String: Any]).map { Xpriv.fromDictionary($0) },
            derivationPath: value["derivationPath"] as? String
        )
    }
}

private extension TransactionOutput {
    static func fromDictionary(_ value: [String: Any]) throws -> TransactionOutput {
        TransactionOutput(
            kind: try TransactionOutputKind.fromRawString(value["kind"] as? String),
            valueKoinu: uint64Value(value["valueKoinu"], default: 0),
            address: value["address"] as? String,
            opReturnDataHex: value["opReturnDataHex"] as? String,
            scriptHex: value["scriptHex"] as? String
        )
    }
}

private extension FeePolicy {
    static func fromDictionary(_ value: [String: Any]) -> FeePolicy {
        FeePolicy(
            feeRateKoinuPerKb: uint64Value(value["feeRateKoinuPerKb"], default: 0),
            dustThresholdKoinu: uint64Value(value["dustThresholdKoinu"], default: 0)
        )
    }
}

private extension ChangeDestination {
    static func fromDictionary(_ value: [String: Any]) -> ChangeDestination {
        ChangeDestination(
            address: value["address"] as? String,
            xpriv: (value["xpriv"] as? [String: Any]).map { Xpriv.fromDictionary($0) },
            derivationPath: value["derivationPath"] as? String
        )
    }
}

private extension TransactionOptions {
    static func fromDictionary(_ value: [String: Any]) -> TransactionOptions {
        TransactionOptions(
            version: Int32(intValue(value["version"], default: 1)),
            lockTime: UInt32(intValue(value["lockTime"], default: 0)),
            sequence: UInt32(uint64Value(value["sequence"], default: UInt64(UInt32.max))),
            sighashType: UInt32(intValue(value["sighashType"], default: 1))
        )
    }
}

private extension ComposeTransactionResult {
    func asDictionary() -> [String: Any] {
        var value: [String: Any] = [
            "network": network.rawString,
            "selectedInputs": selectedInputs.map { $0.asDictionary() },
            "skippedInputs": skippedInputs.map { $0.asDictionary() },
            "inputTotalKoinu": Int(inputTotalKoinu),
            "spendOutputTotalKoinu": Int(spendOutputTotalKoinu),
            "changeAmountKoinu": Int(changeAmountKoinu),
            "feeKoinu": Int(feeKoinu),
            "estimatedSizeBytes": Int(estimatedSizeBytes),
            "dustChangeFoldedIntoFee": dustChangeFoldedIntoFee,
            "unsignedTxHex": unsignedTxHex
        ]
        value["changeAddress"] = changeAddress
        value["changeScriptPubkeyHex"] = changeScriptPubkeyHex
        value["actualSizeBytes"] = actualSizeBytes.map { Int($0) }
        value["signedTxHex"] = signedTxHex
        value["signingEnvelope"] = signingEnvelope?.asDictionary()
        return value
    }
}

private extension AuditedInput {
    func asDictionary() -> [String: Any] {
        [
            "txid": txid,
            "vout": Int(vout),
            "previousOutputValueKoinu": Int(previousOutputValueKoinu),
            "scriptPubkeyHex": scriptPubkeyHex,
            "kind": kind.rawString
        ]
    }
}

private extension SkippedInput {
    func asDictionary() -> [String: Any] {
        [
            "txid": txid,
            "vout": Int(vout),
            "previousOutputValueKoinu": Int(previousOutputValueKoinu),
            "reason": reason
        ]
    }
}

private func intValue(_ value: Any?, default fallback: Int) -> Int {
    if let int = value as? Int {
        return int
    }
    if let double = value as? Double {
        return Int(double)
    }
    return fallback
}

private func uint64Value(_ value: Any?, default fallback: UInt64) -> UInt64 {
    if let uint64 = value as? UInt64 {
        return uint64
    }
    if let int = value as? Int {
        return UInt64(int)
    }
    if let double = value as? Double {
        return UInt64(double)
    }
    if let number = value as? NSNumber {
        return number.uint64Value
    }
    return fallback
}

private func uint64Optional(_ value: Any?) -> UInt64? {
    if value == nil {
        return nil
    }
    return uint64Value(value, default: 0)
}

private func uint8Optional(_ value: Any?) -> UInt8? {
    uint64Optional(value).map { UInt8($0) }
}

private func dictionary(_ value: Any?) -> [String: Any] {
    value as? [String: Any] ?? [:]
}

private func dictionaries(_ value: Any?) -> [[String: Any]] {
    value as? [[String: Any]] ?? []
}

private extension Network {
    var rawString: String {
        switch self {
        case .mainnet: return "mainnet"
        case .testnet: return "testnet"
        case .regtest: return "regtest"
        }
    }
}

private extension Language {
    var rawString: String {
        switch self {
        case .english: return "english"
        case .simplifiedChinese: return "simplified-chinese"
        case .traditionalChinese: return "traditional-chinese"
        case .czech: return "czech"
        case .french: return "french"
        case .italian: return "italian"
        case .japanese: return "japanese"
        case .korean: return "korean"
        case .portuguese: return "portuguese"
        case .spanish: return "spanish"
        }
    }
}
