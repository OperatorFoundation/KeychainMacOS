
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
                print("Our key.type does not match the type. Returning nothing, when we want a key.")
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
            let stored = storePrivateKey(privateKey, label: label, overwrite: true)
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
            guard storePrivateKey(privateKey, label: label,overwrite: true) else
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
    
    public func storePrivateKey(_ key: PrivateKey, label: String, overwrite: Bool = false) -> Bool
    {
        if key.type == .P256SecureEnclaveKeyAgreement
        {
            do
            {
                try storeSecureEnclavePrivateKey(key, label: label, overwrite: overwrite)
                return true
            }
            catch
            {
                return false
            }
        }
        
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
        
        // If a private key already exists, replace it.

        // Add the key to the keychain.
        var status = SecItemAdd(query as CFDictionary, nil)
        
        // If a key already exists, replace it.
        if status == errSecDuplicateItem && overwrite
        {
            status = SecItemUpdate(query as CFDictionary, [kSecValueRef: secKey] as CFDictionary)
        }
        
        switch status
        {
            case errSecSuccess:
                return true
            default:
                let statusDescription = SecCopyErrorMessageString(status, nil)
                print("Failed to store a private key: \(statusDescription ?? status.string as CFString)")
                
                return false
        }
    }
    
    public func retrievePrivateKey(label: String, type: KeyType) -> PrivateKey?
    {
        if type == .P256SecureEnclaveKeyAgreement
        {
            return retrieveSecureEnclavePrivateKey(label: label, type: type)
        }
        
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
    
    /// Secure Enclave Keys have no direct keychain corollary.
    /// To store these keys, package them as generic passwords.
    /// https://developer.apple.com/documentation/cryptokit/storing_cryptokit_keys_in_the_keychain#3369559
    public func storeSecureEnclavePrivateKey(_ key: PrivateKey, label: String, overwrite: Bool) throws
    {
        guard key.type == .P256SecureEnclaveKeyAgreement else
        {
            throw KeychainError.storeSecureEnclaveKeyFailed("Unexpected type: \(key.type)")
        }
        guard let keyData = key.data else
        {
            throw KeychainError.storeSecureEnclaveKeyFailed("The key's data field was nil.")
        }
        
        // Treat the key data as a generic password.
        let query = [kSecClass: kSecClassGenericPassword,
                     kSecAttrAccount: label,
                     kSecAttrAccessible: kSecAttrAccessibleWhenUnlocked,
                     kSecUseDataProtectionKeychain: true,
                 kSecValueData: keyData] as [String: Any]


        // Add the key data.
        var status = SecItemAdd(query as CFDictionary, nil)
        
        // If a key already exists, replace it.
        if status == errSecDuplicateItem && overwrite
        {
            status = SecItemUpdate(query as CFDictionary, [kSecValueData: keyData] as CFDictionary)
        }
        
        guard status == errSecSuccess else
        {
            let statusDescription = SecCopyErrorMessageString(status, nil)
            throw KeychainError.addFailed(statusDescription ?? status.string as CFString)
        }
    }
    
    /// TODO: Currently only supports P256SecureEnclaveKeyAgreement
    public func retrieveSecureEnclavePrivateKey(label: String, type: KeyType) -> PrivateKey?
    {
        guard type == .P256SecureEnclaveKeyAgreement else
        {
            print("Unsupported key type for Secure Enclave retrieval: \(type)")
            return nil
        }
        
        // Seek a generic password with the given account.
        let query = [kSecClass: kSecClassGenericPassword,
                     kSecAttrAccount: label,
                     kSecUseDataProtectionKeychain: true,
                     kSecReturnData: true] as [String: Any]


        // Find and cast the result as data.
        var item: CFTypeRef?
        switch SecItemCopyMatching(query as CFDictionary, &item)
        {
            case errSecSuccess:
                guard let data = item as? Data else { return nil }
                do
                {
                    // Convert back to a key.
                    let storedKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: data)
                         
                    return PrivateKey.P256SecureEnclaveKeyAgreement(storedKey)
                }
                catch
                {
                    print("Failed to decode a stored key: \(error)")
                    return nil
                }

            case let status:
                let statusDescription = SecCopyErrorMessageString(status, nil)
                print("Keychain read failed: \(statusDescription ?? status.string as CFString)")
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

    public func storePassword(server: String, username: String, password: String, overwrite: Bool = false) throws
    {
        let passwordData = password.data
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassInternetPassword,
            kSecAttrAccount as String: username,
            kSecAttrServer as String: server,
            kSecValueData as String: passwordData
        ]

        var status = SecItemAdd(query as CFDictionary, nil)
        
                
        // If a password already exists, replace it.
        if status == errSecDuplicateItem && overwrite
        {
            status = SecItemUpdate(query as CFDictionary, [kSecValueData as String: passwordData] as CFDictionary)
        }
        
        guard status == errSecSuccess else
        {
            let statusDescription = SecCopyErrorMessageString(status, nil)
            throw KeychainError.addFailed(statusDescription ?? status.string as CFString)
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
        
        
        guard status != errSecItemNotFound else
        {
            print("Error: \(errSecItemNotFound)")
            throw KeychainError.noPassword
        }

        guard status == errSecSuccess else
        {
            let statusDescription = SecCopyErrorMessageString(status, nil)
            
            print("DEBUG: Retrieve password item status - \(statusDescription ?? status.string as CFString)")
            
            throw KeychainError.readFailed(statusDescription ?? status.string as CFString)
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
    case addFailed(CFString)
    case deleteFailed(OSStatus)
    case noPassword
    case readFailed(CFString)
    case unexpectedPasswordData
    case storeSecureEnclaveKeyFailed(String)
}
