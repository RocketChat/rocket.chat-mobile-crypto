import Foundation
import CryptoKit

package enum AESGCMCrypto {
  private static let nonceLength = 12
  private static let tagLength = 16

  package static func encrypt(_ plaintext: String, key: Data) -> (iv: String, ciphertext: String)? {
    guard let nonce = RandomGenerator.bytes(count: nonceLength),
          let ciphertextAndTag = encrypt(Data(plaintext.utf8), key: key, nonce: nonce) else {
      return nil
    }
    return (iv: nonce.base64EncodedString(), ciphertext: ciphertextAndTag.base64EncodedString())
  }

  package static func decrypt(_ ciphertextBase64: String, ivBase64: String, key: Data) -> String? {
    guard let ciphertextAndTag = Data(base64Encoded: ciphertextBase64),
          let nonce = Data(base64Encoded: ivBase64),
          let plaintext = decrypt(ciphertextAndTag, key: key, nonce: nonce) else {
      return nil
    }
    return String(data: plaintext, encoding: .utf8)
  }

  private static func encrypt(_ plaintext: Data, key: Data, nonce: Data) -> Data? {
    guard let gcmNonce = try? AES.GCM.Nonce(data: nonce),
          let sealedBox = try? AES.GCM.seal(plaintext, using: SymmetricKey(data: key), nonce: gcmNonce) else {
      return nil
    }
    return sealedBox.ciphertext + sealedBox.tag
  }

  private static func decrypt(_ ciphertextAndTag: Data, key: Data, nonce: Data) -> Data? {
    guard nonce.count == nonceLength,
          ciphertextAndTag.count >= tagLength,
          let gcmNonce = try? AES.GCM.Nonce(data: nonce),
          let sealedBox = try? AES.GCM.SealedBox(
            nonce: gcmNonce,
            ciphertext: ciphertextAndTag.prefix(ciphertextAndTag.count - tagLength),
            tag: ciphertextAndTag.suffix(tagLength)
          ) else {
      return nil
    }
    return try? AES.GCM.open(sealedBox, using: SymmetricKey(data: key))
  }
}
