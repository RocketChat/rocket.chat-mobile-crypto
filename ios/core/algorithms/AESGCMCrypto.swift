import Foundation
import CryptoKit

package enum AESGCMCrypto {
  private static let nonceLength = 12
  private static let tagLength = 16
  private static let stringKeyLength = 32

  package static func encrypt(_ plaintext: Data, key: Data, nonce: Data) -> Data? {
    guard nonce.count == nonceLength,
          let gcmNonce = try? AES.GCM.Nonce(data: nonce),
          let sealedBox = try? AES.GCM.seal(plaintext, using: SymmetricKey(data: key), nonce: gcmNonce) else {
      return nil
    }
    return sealedBox.ciphertext + sealedBox.tag
  }

  package static func decrypt(_ ciphertextAndTag: Data, key: Data, nonce: Data) -> Data? {
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

  package static func encryptBase64(_ dataBase64: String, keyHex: String, ivHex: String) -> String? {
    guard let (input, key, nonce) = decodeStringArguments(dataBase64, keyHex: keyHex, ivHex: ivHex) else { return nil }
    return encrypt(input, key: key, nonce: nonce)?.base64EncodedString()
  }

  package static func decryptBase64(_ dataBase64: String, keyHex: String, ivHex: String) -> String? {
    guard let (input, key, nonce) = decodeStringArguments(dataBase64, keyHex: keyHex, ivHex: ivHex) else { return nil }
    return decrypt(input, key: key, nonce: nonce)?.base64EncodedString()
  }

  private static func decodeStringArguments(_ dataBase64: String, keyHex: String, ivHex: String) -> (Data, Data, Data)? {
    guard !dataBase64.isEmpty,
          let input = Data(base64Encoded: dataBase64),
          let key = Data(hexString: keyHex),
          key.count == stringKeyLength,
          let nonce = Data(hexString: ivHex) else {
      return nil
    }
    return (input, key, nonce)
  }
}
