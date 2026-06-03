import Testing
@testable import EasyDogeKM

@Test func packageLoads() async throws {
    let sdk = EasyDogeKM()
    let valid = try validateMnemonic(
        phrase: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        language: .english
    )
    #expect(valid)

    let keys = try sdk.accountKeys(
        phrase: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        passphrase: "TREZOR"
    )
    let address = try deriveAddressFromXpub(xpub: keys.xpub, path: "m/0/0")
    #expect(address.address == "DMn7J63QSZUR9XNxsUJtvsttZVzV9Am4qM")
}
