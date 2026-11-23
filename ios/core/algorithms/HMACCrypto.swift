import Foundation
import CryptoKit

package enum HMACCrypto {
  package static func hmacSha256(_ content: Data, key: Data) -> Data {
    Data(HMAC<SHA256>.authenticationCode(for: content, using: SymmetricKey(data: key)))
  }
}
