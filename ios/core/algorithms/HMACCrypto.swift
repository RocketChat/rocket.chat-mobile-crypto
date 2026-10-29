import Foundation
import CryptoKit

package enum HMACCrypto {
  package static func hmacSha256(_ content: Data, key: Data) -> Data {
    Data(HMAC<SHA256>.authenticationCode(for: content, using: SymmetricKey(data: key)))
  }

  package static func hmacSha256Hex(_ dataHex: String, keyHex: String) -> String? {
    guard let content = Data(hexString: dataHex), let key = Data(hexString: keyHex) else { return nil }
    return hmacSha256(content, key: key).lowercaseHexString
  }
}
