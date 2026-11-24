import Foundation
import Security

package enum RSACrypto {
  private static let encryptionAlgorithm = SecKeyAlgorithm.rsaEncryptionOAEPSHA256
  private static let jwtAlgorithm = "RS256"

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

  package static func encrypt(_ plaintext: String, using publicKey: SecKey) -> String? {
    guard SecKeyIsAlgorithmSupported(publicKey, .encrypt, encryptionAlgorithm),
          let ciphertext = SecKeyCreateEncryptedData(publicKey, encryptionAlgorithm, Data(plaintext.utf8) as CFData, nil) as Data? else {
      return nil
    }
    return ciphertext.base64EncodedString()
  }

  package static func decrypt(_ ciphertextBase64: String, using privateKey: SecKey) -> String? {
    guard SecKeyIsAlgorithmSupported(privateKey, .decrypt, encryptionAlgorithm),
          let ciphertext = Data(canonicalBase64: ciphertextBase64),
          let plaintext = SecKeyCreateDecryptedData(privateKey, encryptionAlgorithm, ciphertext as CFData, nil) as Data? else {
      return nil
    }
    return String(strictUTF8: plaintext)
  }

  package static func sign(_ message: Data, using privateKey: SecKey, hash: RSAHashAlgorithm) -> Data? {
    SecKeyCreateSignature(privateKey, hash.signatureAlgorithm, message as CFData, nil) as Data?
  }

  package static func verify(_ signature: Data, message: Data, using publicKey: SecKey, hash: RSAHashAlgorithm) -> Bool {
    SecKeyVerifySignature(publicKey, hash.signatureAlgorithm, message as CFData, signature as CFData, nil)
  }

  package static func verifiedJwtPayload(_ jwt: String, using publicKey: SecKey) -> String? {
    let segments = jwt.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
    guard segments.count == 3,
          let header = Data(base64URLEncoded: segments[0]),
          (try? JSONDecoder().decode(JWTHeader.self, from: header))?.alg == jwtAlgorithm,
          let signature = Data(base64URLEncoded: segments[2]),
          verify(signature, message: Data("\(segments[0]).\(segments[1])".utf8), using: publicKey, hash: .sha256),
          let payload = Data(base64URLEncoded: segments[1]) else {
      return nil
    }
    return String(strictUTF8: payload)
  }
}
