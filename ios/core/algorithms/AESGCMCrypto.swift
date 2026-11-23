import Foundation
import CryptoKit

package enum AESGCMCrypto {
  private static let nonceLength = 12

  package static func encrypt(_ plaintext: String, key: Data) -> (iv: String, ciphertext: String)? {
    guard AESKeyFactory.isValid(key),
          let sealedBox = try? AES.GCM.seal(Data(plaintext.utf8), using: SymmetricKey(data: key)) else {
      return nil
    }
    return (
      iv: Data(sealedBox.nonce).base64EncodedString(),
      ciphertext: (sealedBox.ciphertext + sealedBox.tag).base64EncodedString()
    )
  }

  package static func decrypt(_ ciphertextBase64: String, ivBase64: String, key: Data) -> String? {
    guard AESKeyFactory.isValid(key),
          let ciphertextAndTag = Data(canonicalBase64: ciphertextBase64),
          let nonce = Data(canonicalBase64: ivBase64),
          nonce.count == nonceLength,
          let sealedBox = try? AES.GCM.SealedBox(combined: nonce + ciphertextAndTag),
          let plaintext = try? AES.GCM.open(sealedBox, using: SymmetricKey(data: key)) else {
      return nil
    }
    return String(strictUTF8: plaintext)
  }
}
