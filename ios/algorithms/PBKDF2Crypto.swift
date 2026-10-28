import Foundation
import CommonCrypto

enum PBKDF2Crypto {
  static func deriveKeyBase64(
    _ passwordBase64: String,
    saltBase64: String,
    iterations: UInt,
    keyLength: UInt,
    hash: PBKDF2HashAlgorithm
  ) -> String? {
    guard let password = Data(base64Encoded: passwordBase64),
          let salt = Data(base64Encoded: saltBase64),
          keyLength > 0,
          iterations > 0 else {
      return nil
    }
    var derivedKey = Data(count: Int(keyLength))
    let derivedKeyLength = derivedKey.count
    let status = derivedKey.withUnsafeMutableBytes { derivedKeyBytes in
      password.withUnsafeBytes { passwordBytes in
        salt.withUnsafeBytes { saltBytes in
          CCKeyDerivationPBKDF(
            CCPBKDFAlgorithm(kCCPBKDF2),
            passwordBytes.bindMemory(to: CChar.self).baseAddress,
            password.count,
            saltBytes.bindMemory(to: UInt8.self).baseAddress,
            salt.count,
            hash.pseudoRandomAlgorithm,
            UInt32(truncatingIfNeeded: iterations),
            derivedKeyBytes.bindMemory(to: UInt8.self).baseAddress,
            derivedKeyLength
          )
        }
      }
    }
    guard status == kCCSuccess else { return nil }
    return derivedKey.base64EncodedString()
  }
}
