
import Crypto
import Foundation

import Datable
import KeychainTypes

public class Keychain: Codable, KeychainProtocol
{
    public init()
    {
    }

    public func generateEphemeralKeypair(type: KeyType) -> Keypair?
    {
        do
        {
            var privateKey: PrivateKey? = nil
            while privateKey == nil
            {
                let tempPrivateKey = try PrivateKey(type: type)
                guard tempPrivateKey.data != nil else
                {
                    continue
                }
                privateKey = tempPrivateKey
            }

            guard let privateKey = privateKey else
            {
                return nil
            }

            return Keypair(privateKey: privateKey, publicKey: privateKey.publicKey)
        }
        catch
        {
            return nil
        }
    }

    public func retrieveOrGeneratePrivateKey(label: String, type: KeyType) -> PrivateKey?
    {
        // Do we already have a key?
        if let key = retrievePrivateKey(label: label, type: type)
        {
            guard key.type == type else
            {
                return nil
            }

            return key
        }

        do
        {
            // We don't?
            // Let's create some and return those
            var privateKey: PrivateKey? = nil
            while privateKey == nil
            {
                let tempPrivateKey = try PrivateKey(type: type)
                guard tempPrivateKey.data != nil else
                {
                    continue
                }
                privateKey = tempPrivateKey
            }

            guard let privateKey = privateKey else
            {
                return nil
            }

            // Save the key we stored
            let stored = storePrivateKey(privateKey, label: label)
            if !stored
            {
                print("😱 Failed to store our new server key.")
                return nil
            }
            return privateKey
        }
        catch
        {
            return nil
        }
    }
    
    public func generateAndSavePrivateKey(label: String, type: KeyType) -> PrivateKey?
    {
        do
        {
            var privateKey: PrivateKey? = nil
            while privateKey == nil
            {
                let tempPrivateKey = try PrivateKey(type: type)
                guard tempPrivateKey.data != nil else
                {
                    continue
                }
                privateKey = tempPrivateKey
            }

            guard let privateKey = privateKey else
            {
                return nil
            }

            // Save the key we stored
            guard storePrivateKey(privateKey, label: label) else
            {
                print("😱 Failed to store our new server key.")
                return nil
            }

            return privateKey
        }
        catch
        {
            return nil
        }
    }
    
    public func storePrivateKey(_ key: PrivateKey, label: String) -> Bool
    {
        let attributes = [kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeyClass: kSecAttrKeyClassPrivate] as [String: Any]

        // Get a SecKey representation.
        var error: Unmanaged<CFError>?
        guard let data = key.x963 else
        {
            return false
        }
        let keyData = data as CFData
        guard let secKey = SecKeyCreateWithData(keyData, attributes as CFDictionary, &error) else
        {
            print("Unable to create SecKey representation.")
            if let secKeyError = error
            {
                print(secKeyError)
            }

            return false
        }
        
        // Describe the add operation.
        let query = [kSecClass: kSecClassKey,
                     kSecAttrApplicationLabel: label,
                     kSecAttrAccessible: kSecAttrAccessibleWhenUnlocked,
                     kSecUseDataProtectionKeychain: true,
                     kSecValueRef: secKey] as [String: Any]

        // Add the key to the keychain.
        let status = SecItemAdd(query as CFDictionary, nil)
        
        switch status {
        case errSecSuccess:
            return true
        default:
            if let statusString = SecCopyErrorMessageString(status, nil)
            {
                print("Unable to store item: \(statusString)")
            }
            
            return false
        }
    }
    
    public func retrievePrivateKey(label: String, type: KeyType) -> PrivateKey?
    {
        let query: CFDictionary = generateKeySearchQuery(label: label)
        
        // Find and cast the result as a SecKey instance.
        var item: CFTypeRef?
        var secKey: SecKey
        switch SecItemCopyMatching(query as CFDictionary, &item)
        {
            case errSecSuccess:
                secKey = item as! SecKey
            case errSecItemNotFound:
                return nil
            case let status:
                print("Keychain read failed: \(status)")
                return nil
        }
        
        // Convert the SecKey into a CryptoKit key.
        var error: Unmanaged<CFError>?
        guard let data = SecKeyCopyExternalRepresentation(secKey, &error) as Data? else
        {
            print(error.debugDescription)
            return nil
        }
        
        do
        {
            let key = try PrivateKey(typedData: data)

            guard key.type == type else
            {
                return nil
            }

            return key
        }
        catch let keyError
        {
            print("Error decoding key: \(keyError)")
            return nil
        }
    }
    
    public func generateKeySearchQuery(label: String) -> CFDictionary
    {
        let query: [String: Any] = [kSecClass as String: kSecClassKey,
                                    kSecAttrApplicationLabel as String: label,
                                    //kSecAttrApplicationTag as String: tag,
                                    kSecMatchLimit as String: kSecMatchLimitOne,
                                    kSecReturnRef as String: true,
                                    kSecReturnAttributes as String: false,
                                    kSecReturnData as String: false]
        
        return query as CFDictionary
    }
    
    public func deleteKey(label: String)
    {
        print("\nAttempted to delete key.")
        //Remove client keys from secure enclave
        //let query: [String: Any] = [kSecClass as String: kSecClassKey, kSecAttrApplicationTag as String: tag]
        let query = generateKeySearchQuery(label: label)
        let deleteStatus = SecItemDelete(query as CFDictionary)
        
        switch deleteStatus
        {
        case errSecItemNotFound:
            print("Could not find a key to delete.\n")
        case noErr:
            print("Deleted a key.\n")
        default:
            print("Unexpected status: \(deleteStatus.description)\n")
        }
    }

    public func storePassword(server: String, username: String, password: String) throws
    {
        let query: [String: Any] = [
            kSecClass as String: kSecClassInternetPassword,
            kSecAttrAccount as String: username,
            kSecAttrServer as String: server,
            kSecValueData as String: password
        ]

        let status = SecItemAdd(query as CFDictionary, nil)
        let statusDescription = SecCopyErrorMessageString(status, nil)
        guard status == errSecSuccess else
        {
            throw KeychainError.addFailed(status)
        }
    }

    public func retrievePassword(server: String) throws -> (username: String, password: String)
    {
        let query: [String: Any] = [
            kSecClass as String: kSecClassInternetPassword,
            kSecAttrServer as String: server,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecReturnAttributes as String: true,
            kSecReturnData as String: true
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        print("DEBUG: Retrieve password item status - \(status.string)")
        guard status != errSecItemNotFound else
        {
            print("Error: \(errSecItemNotFound)")
            throw KeychainError.noPassword
        }

        guard status == errSecSuccess else
        {
            throw KeychainError.readFailed(status)
        }

        guard let existingItem = item as? [String : Any],
              let passwordData = existingItem[kSecValueData as String] as? Data,
              let password = String(data: passwordData, encoding: String.Encoding.utf8),
              let account = existingItem[kSecAttrAccount as String] as? String
        else
        {
            throw KeychainError.unexpectedPasswordData
        }

        return (username: account, password: password)
    }

    public func deletePassword(server: String) throws
    {
        let query: [String: Any] = [
            kSecClass as String: kSecClassInternetPassword,
            kSecAttrServer as String: server
        ]

        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else
        {
            throw KeychainError.deleteFailed(status)
        }
    }

    public func newSymmetricKey(sizeInBits: Int) -> SymmetricKey
    {
        let size = SymmetricKeySize(bitCount: sizeInBits)
        let key = SymmetricKey(size: size)
        return key
    }

    public func hmac(digest: DigestType, key: SymmetricKey, data: Data) -> AuthenticationCode
    {
        switch digest
        {
            case .SHA256:
                let hmac = HMAC<SHA256>.authenticationCode(for: data, using: key)
                let hmacData = Data(hmac)
                return AuthenticationCode(type: digest, code: hmacData)

            case .SHA384:
                let hmac = HMAC<SHA384>.authenticationCode(for: data, using: key)
                let hmacData = Data(hmac)
                return AuthenticationCode(type: digest, code: hmacData)

            case .SHA512:
                let hmac = HMAC<SHA512>.authenticationCode(for: data, using: key)
                let hmacData = Data(hmac)
                return AuthenticationCode(type: digest, code: hmacData)
        }
    }
}

public enum KeychainError: Error
{
    case addFailed(OSStatus)
    case deleteFailed(OSStatus)
    case noPassword
    case readFailed(OSStatus)
    case unexpectedPasswordData
}
