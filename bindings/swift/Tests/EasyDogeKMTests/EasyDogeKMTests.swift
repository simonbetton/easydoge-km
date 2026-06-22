import Foundation
import Testing
@testable import EasyDogeKM

@Test func packageLoadsAndWrapperSurfaceMatchesParityVectors() async throws {
    let vectors = try parityVectors()
    let mnemonic = object(vectors, "mnemonic")
    let account = object(mnemonic, "account")
    let receive = object(mnemonic, "receive")
    let message = object(vectors, "message")
    let transaction = object(vectors, "transaction")
    let multisig = object(vectors, "multisig")

    let sdk = EasyDogeKM()
    let phrase = string(mnemonic, "phrase")
    let valid = try sdk.validateMnemonic(phrase: phrase)
    #expect(valid)

    let keys = try sdk.accountKeys(
        phrase: phrase,
        passphrase: string(mnemonic, "passphrase")
    )
    #expect(keys.xpriv.encoded == string(account, "xpriv"))
    #expect(keys.xpub.encoded == string(account, "xpub"))

    let address = try sdk.deriveAddressFromXpub(xpub: keys.xpub, path: string(receive, "relative_path"))
    #expect(address.address == string(receive, "address"))

    let info = try sdk.inspectXpriv(xpriv: keys.xpriv)
    #expect(info.privateKeyRedacted)
    #expect(info.publicKeyHex == string(account, "public_key_hex"))

    let wif = try sdk.wifFromXpriv(xpriv: keys.xpriv)
    #expect(wif == string(account, "wif"))
    #expect(try sdk.addressFromWif(wif: wif).address == string(account, "address"))

    let signature = try sdk.signMessage(wif: wif, message: string(message, "text"))
    #expect(signature.signatureBase64 == string(message, "signature_base64"))
    #expect(try sdk.verifyMessage(
        address: signature.address,
        signatureBase64: signature.signatureBase64,
        message: string(message, "text")
    ))

    let signed = try sdk.signP2pkhTransaction(
        unsignedTxHex: string(transaction, "unsigned_tx_hex"),
        inputIndex: UInt64(int(transaction, "input_index")),
        scriptPubkeyHex: string(transaction, "script_pubkey_hex"),
        wif: wif,
        sighashType: UInt32(int(transaction, "sighash_type"))
    )
    #expect(signed.signedTxHex == string(transaction, "signed_tx_hex"))

    let envelope = SigningEnvelope(
        version: 1,
        network: .mainnet,
        unsignedTxHex: string(transaction, "unsigned_tx_hex"),
        inputs: [
            SigningEnvelopeInput(
                inputIndex: UInt64(int(transaction, "input_index")),
                kind: .p2pkh,
                scriptPubkeyHex: string(transaction, "script_pubkey_hex"),
                redeemScriptHex: nil,
                sighashType: UInt32(int(transaction, "sighash_type")),
                previousOutputValueKoinu: nil,
                multisigThreshold: nil,
                multisigPublicKeysHex: []
            )
        ],
        signatures: []
    )
    let signedEnvelope = try sdk.signSigningEnvelope(envelope: envelope, wif: wif)
    let combined = try sdk.combineSigningEnvelopes(envelopes: [signedEnvelope, signedEnvelope])
    #expect(combined.signatures.count == 1)
    #expect(try sdk.finalizeSigningEnvelope(envelope: combined).signedTxHex == string(transaction, "signed_tx_hex"))

    let cosignerXpubs = stringArray(multisig, "cosigner_xpubs").map {
        Xpub(network: .mainnet, encoded: $0)
    }
    let descriptor = try sdk.createMultisigDescriptor(
        threshold: UInt8(int(multisig, "threshold")),
        cosignerXpubs: cosignerXpubs,
        childPath: string(multisig, "child_path")
    )
    #expect(descriptor.p2shAddress == string(multisig, "p2sh_address"))
    #expect(descriptor.redeemScriptHex == string(multisig, "redeem_script_hex"))
}

private func parityVectors() throws -> [String: Any] {
    let root = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
    let data = try Data(contentsOf: root.appendingPathComponent("test-vectors/parity.json"))
    return try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
}

private func object(_ value: [String: Any], _ key: String) -> [String: Any] {
    value[key] as? [String: Any] ?? [:]
}

private func string(_ value: [String: Any], _ key: String) -> String {
    value[key] as? String ?? ""
}

private func int(_ value: [String: Any], _ key: String) -> Int {
    value[key] as? Int ?? 0
}

private func stringArray(_ value: [String: Any], _ key: String) -> [String] {
    value[key] as? [String] ?? []
}
