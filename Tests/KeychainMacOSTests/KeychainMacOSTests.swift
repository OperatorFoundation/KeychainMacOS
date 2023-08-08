import XCTest

import KeychainTypes
@testable import KeychainMacOS

final class KeychainMacOSTests: XCTestCase {
    func testPrivateKey()
    {
        let keychain = Keychain()
        let key1 = keychain.generateAndSavePrivateKey(label: "test", type: KeyType.P256KeyAgreement)
        let key2 = keychain.retrieveOrGeneratePrivateKey(label: "test", type: KeyType.P256KeyAgreement)

        XCTAssertEqual(key1, key2)
    }
    
    func testStorePassword() throws
    {
        let password = "1234"
        
        try Keychain().storePassword(server: "KeychainServer", username: "KeychainUsername", password: password)
    }
}
