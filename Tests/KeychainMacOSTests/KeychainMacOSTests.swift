import XCTest
@testable import KeychainMacOS

final class KeychainMacOSTests: XCTestCase {
    func testExample()
    {
        let keychain = Keychain()
        let key1 = keychain.generateAndSavePrivateSigningKey(label: "test")
        let key2 = keychain.retrieveOrGeneratePrivateSigningKey(label: "test")

        XCTAssertEqual(key1, key2)
    }
}
