import Foundation

public struct AESKey {
  private static let validByteLengths: Set<Int> = [16, 32]

  package let data: Data

  package init?(data: Data) {
    guard Self.validByteLengths.contains(data.count) else { return nil }
    self.data = data
  }

  package init?(base64URL: String) {
    guard let data = Data(base64URLEncoded: base64URL) else { return nil }
    self.init(data: data)
  }

  package static func generate(byteLength: Int) -> AESKey? {
    guard validByteLengths.contains(byteLength),
          let data = RandomGenerator.bytes(count: byteLength) else { return nil }
    return AESKey(data: data)
  }

  package static func derive(
    passwordBase64: String,
    saltBase64: String,
    iterations: Int,
    byteLength: Int,
    hash: PBKDF2HashAlgorithm
  ) -> AESKey? {
    guard validByteLengths.contains(byteLength),
          let password = Data(canonicalBase64: passwordBase64),
          let salt = Data(canonicalBase64: saltBase64),
          let data = PBKDF2Crypto.deriveKey(password: password, salt: salt, iterations: iterations, keyLength: byteLength, hash: hash) else { return nil }
    return AESKey(data: data)
  }

  package var base64URL: String {
    data.base64URLEncodedString
  }
}
