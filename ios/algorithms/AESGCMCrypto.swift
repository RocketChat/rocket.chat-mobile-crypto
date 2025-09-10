import Foundation
import CryptoKit

/**
 * AES-256-GCM encryption and decryption operations using CryptoKit
 * This class provides compatibility with the Android GCM implementation
 */
@objc public class AESGCMCrypto: NSObject {
    
    /**
     * Encrypt Base64-encoded data using AES-256-GCM
     * @param dataBase64 The Base64-encoded plaintext to encrypt
     * @param keyHex The 256-bit (32 bytes) key in hexadecimal format
     * @param ivHex The 96-bit (12 bytes) IV in hexadecimal format, or nil to use zero IV
     * @return Base64-encoded encrypted data with authentication tag, or nil on error
     */
    @objc public static func encryptGcmBase64(_ dataBase64: String?, keyHex: String, ivHex: String?) -> String? {
        guard let dataBase64 = dataBase64, !dataBase64.isEmpty else {
            return nil
        }
        
        // Decode Base64 input data
        guard let inputData = Data(base64Encoded: dataBase64) else {
            return nil
        }
        
        // Convert hex key to Data (32 bytes for AES-256)
        guard let keyData = Data(hexString: keyHex), keyData.count == 32 else {
            return nil
        }
        
        // Convert hex IV to Data (12 bytes for GCM)
        let ivData: Data
        if let ivHex = ivHex {
            guard let iv = Data(hexString: ivHex), iv.count == 12 else {
                return nil
            }
            ivData = iv
        } else {
            // Use zero IV if not provided
            ivData = Data(repeating: 0, count: 12)
        }
        
        do {
            // Create symmetric key
            let symmetricKey = SymmetricKey(data: keyData)
            
            // Create nonce from IV
            let nonce = try AES.GCM.Nonce(data: ivData)
            
            // Encrypt the data
            let sealedBox = try AES.GCM.seal(inputData, using: symmetricKey, nonce: nonce)
            
            // Combine ciphertext and tag
            var combinedData = sealedBox.ciphertext
            combinedData.append(sealedBox.tag)
            
            // Return Base64-encoded result
            return combinedData.base64EncodedString()
        } catch {
            // Return nil on any encryption error
            return nil
        }
    }
    
    /**
     * Decrypt Base64-encoded data using AES-256-GCM
     * @param ciphertext The Base64-encoded ciphertext with authentication tag to decrypt
     * @param keyHex The 256-bit (32 bytes) key in hexadecimal format
     * @param ivHex The 96-bit (12 bytes) IV in hexadecimal format, or nil to use zero IV
     * @return Base64-encoded decrypted data, or nil on error or authentication failure
     */
    @objc public static func decryptGcmBase64(_ ciphertext: String?, keyHex: String, ivHex: String?) -> String? {
        guard let ciphertext = ciphertext, !ciphertext.isEmpty else {
            return nil
        }
        
        // Decode Base64 ciphertext
        guard let combinedData = Data(base64Encoded: ciphertext) else {
            return nil
        }
        
        // Extract ciphertext and tag (last 16 bytes)
        guard combinedData.count >= 16 else {
            return nil
        }
        
        let ciphertextData = combinedData.prefix(combinedData.count - 16)
        let tagData = combinedData.suffix(16)
        
        // Convert hex key to Data (32 bytes for AES-256)
        guard let keyData = Data(hexString: keyHex), keyData.count == 32 else {
            return nil
        }
        
        // Convert hex IV to Data (12 bytes for GCM)
        let ivData: Data
        if let ivHex = ivHex {
            guard let iv = Data(hexString: ivHex), iv.count == 12 else {
                return nil
            }
            ivData = iv
        } else {
            // Use zero IV if not provided
            ivData = Data(repeating: 0, count: 12)
        }
        
        do {
            // Create symmetric key
            let symmetricKey = SymmetricKey(data: keyData)
            
            // Create nonce from IV
            let nonce = try AES.GCM.Nonce(data: ivData)
            
            // Create sealed box from components
            let sealedBox = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertextData, tag: tagData)
            
            // Decrypt the data
            let decryptedData = try AES.GCM.open(sealedBox, using: symmetricKey)
            
            // Return Base64-encoded result
            return decryptedData.base64EncodedString()
        } catch {
            // Return nil on any decryption error (including authentication failure)
            return nil
        }
    }
}

// MARK: - Data Extension for Hex Conversion
extension Data {
    /**
     * Initialize Data from hexadecimal string
     */
    init?(hexString: String) {
        let cleanHex = hexString.replacingOccurrences(of: " ", with: "")
        guard cleanHex.count % 2 == 0 else { return nil }
        
        var data = Data()
        var index = cleanHex.startIndex
        
        while index < cleanHex.endIndex {
            let nextIndex = cleanHex.index(index, offsetBy: 2)
            let byteString = String(cleanHex[index..<nextIndex])
            
            guard let byte = UInt8(byteString, radix: 16) else { return nil }
            data.append(byte)
            index = nextIndex
        }
        
        self = data
    }
}
