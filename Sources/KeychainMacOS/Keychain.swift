
import Crypto
import Foundation

import KeychainTypes

public class Keychain: Codable, KeychainProtocol
{
    public init()
    {
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
            let privateKey = try PrivateKey(type: type)

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
            let privateKey = try PrivateKey(type: type)

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
    
    public func storePrivateKey(_ key: PrivateKey, label: String) -> Bool
    {
        let attributes = [kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
                          kSecAttrKeyClass: kSecAttrKeyClassPrivate] as [String: Any]

        // Get a SecKey representation.
        var error: Unmanaged<CFError>?
        guard let data = key.typedData else
        {
            return false
        }
        let keyData = data as CFData
        guard let secKey = SecKeyCreateWithData(keyData,
                                                attributes as CFDictionary,
                                                &error)
            else
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
}
