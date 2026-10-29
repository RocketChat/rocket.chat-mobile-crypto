import Foundation
import Security

package enum RSACrypto {
  private static let encryptionAlgorithm = SecKeyAlgorithm.rsaEncryptionOAEPSHA256

  package static func generateKeyPair(bitCount: Int) -> RSAKeyPair? {
    let attributes: [CFString: Any] = [
      kSecAttrKeyType: kSecAttrKeyTypeRSA,
      kSecAttrKeySizeInBits: bitCount,
      kSecPrivateKeyAttrs: [CFString: Any](),
    ]
    guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, nil),
          let publicKey = SecKeyCopyPublicKey(privateKey) else {
      return nil
    }
    return RSAKeyPair(publicKey: publicKey, privateKey: privateKey)
  }

  package static func externalRepresentation(of key: SecKey) -> Data? {
    SecKeyCopyExternalRepresentation(key, nil) as Data?
  }

  package static func encrypt(_ plaintext: String, using publicKey: SecKey) -> String? {
    guard SecKeyIsAlgorithmSupported(publicKey, .encrypt, encryptionAlgorithm),
          let ciphertext = SecKeyCreateEncryptedData(publicKey, encryptionAlgorithm, Data(plaintext.utf8) as CFData, nil) as Data? else {
      return nil
    }
    return ciphertext.base64EncodedString()
  }

  package static func decrypt(_ ciphertextBase64: String, using privateKey: SecKey) -> String? {
    guard SecKeyIsAlgorithmSupported(privateKey, .decrypt, encryptionAlgorithm),
          let ciphertext = Data(base64Encoded: ciphertextBase64),
          let plaintext = SecKeyCreateDecryptedData(privateKey, encryptionAlgorithm, ciphertext as CFData, nil) as Data? else {
      return nil
    }
    return String(data: plaintext, encoding: .utf8)
  }

  package static func sign(_ message: Data, using privateKey: SecKey, hash: RSAHashAlgorithm) -> Data? {
    SecKeyCreateSignature(privateKey, hash.signatureAlgorithm, message as CFData, nil) as Data?
  }

  package static func verify(_ signature: Data, message: Data, using publicKey: SecKey, hash: RSAHashAlgorithm) -> Bool {
    SecKeyVerifySignature(publicKey, hash.signatureAlgorithm, message as CFData, signature as CFData, nil)
  }
}
