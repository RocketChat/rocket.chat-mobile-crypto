import Foundation

package enum AESKeyFactory {
  private static let validByteLengths: Set<Int> = [16, 24, 32]

  package static func generate(byteLength: Int) -> Data? {
    guard validByteLengths.contains(byteLength) else { return nil }
    return RandomGenerator.bytes(count: byteLength)
  }

  package static func importBase64URL(_ base64URL: String) -> Data? {
    guard let key = Data(base64URLEncoded: base64URL), validByteLengths.contains(key.count) else { return nil }
    return key
  }

  package static func derive(
    passwordBase64: String,
    saltBase64: String,
    iterations: Int,
    byteLength: Int,
    hash: PBKDF2HashAlgorithm
  ) -> Data? {
    guard validByteLengths.contains(byteLength),
          let password = Data(base64Encoded: passwordBase64),
          let salt = Data(base64Encoded: saltBase64) else { return nil }
    return PBKDF2Crypto.deriveKey(password: password, salt: salt, iterations: iterations, keyLength: byteLength, hash: hash)
  }
}
