import Foundation
import Security

enum RSACrypto {
  private static let encryptionAlgorithm = SecKeyAlgorithm.rsaEncryptionOAEPSHA256

  static func generateKeyPair(bitCount: Int) -> RSAKeyPair? {
    let attributes: [CFString: Any] = [
      kSecAttrKeyType: kSecAttrKeyTypeRSA,
      kSecAttrKeySizeInBits: bitCount,
      kSecPrivateKeyAttrs: [CFString: Any](),
    ]
    guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, nil),
          let publicKey = SecKeyCopyPublicKey(privateKey),
          let privateKeyData = externalRepresentation(of: privateKey),
          let publicKeyData = externalRepresentation(of: publicKey) else {
      return nil
    }
    return RSAKeyPair(
      publicKey: RSAPem.format(publicKeyData, tag: "PUBLIC"),
      privateKey: RSAPem.format(privateKeyData, tag: "PRIVATE")
    )
  }

  static func externalRepresentation(of key: SecKey) -> Data? {
    SecKeyCopyExternalRepresentation(key, nil) as Data?
  }

  static func encrypt(_ plaintext: Data, using publicKey: SecKey) -> Data? {
    guard SecKeyIsAlgorithmSupported(publicKey, .encrypt, encryptionAlgorithm) else { return nil }
    return SecKeyCreateEncryptedData(publicKey, encryptionAlgorithm, plaintext as CFData, nil) as Data?
  }

  static func decrypt(_ ciphertext: Data, using privateKey: SecKey) -> Data? {
    guard SecKeyIsAlgorithmSupported(privateKey, .decrypt, encryptionAlgorithm) else { return nil }
    return SecKeyCreateDecryptedData(privateKey, encryptionAlgorithm, ciphertext as CFData, nil) as Data?
  }

  static func sign(_ message: Data, using privateKey: SecKey, hash: RSAHashAlgorithm) -> Data? {
    SecKeyCreateSignature(privateKey, hash.signatureAlgorithm, message as CFData, nil) as Data?
  }

  static func verify(_ signature: Data, message: Data, using publicKey: SecKey, hash: RSAHashAlgorithm) -> Bool {
    SecKeyVerifySignature(publicKey, hash.signatureAlgorithm, message as CFData, signature as CFData, nil)
  }
}
