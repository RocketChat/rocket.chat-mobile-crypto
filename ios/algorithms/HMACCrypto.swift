import Foundation
import CryptoKit

enum HMACCrypto {
  static func hmacSha256Hex(_ dataHex: String, keyHex: String) -> String? {
    guard let content = Data(hexString: dataHex), let key = Data(hexString: keyHex) else { return nil }
    let authenticationCode = HMAC<SHA256>.authenticationCode(for: content, using: SymmetricKey(data: key))
    return Data(authenticationCode).lowercaseHexString
  }
}
