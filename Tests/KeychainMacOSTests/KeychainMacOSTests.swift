import XCTest

import KeychainTypes
@testable import KeychainMacOS

final class KeychainMacOSTests: XCTestCase {
    func testExample()
    {
        let keychain = Keychain()
        let key1 = keychain.generateAndSavePrivateKey(label: "test", type: KeyType.P256KeyAgreement)
        let key2 = keychain.retrieveOrGeneratePrivateKey(label: "test", type: KeyType.P256KeyAgreement)

        XCTAssertEqual(key1, key2)
    }
}
