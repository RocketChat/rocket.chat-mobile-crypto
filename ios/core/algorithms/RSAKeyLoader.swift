import Foundation
import Security

package enum RSAKeyLoader {
  package static func key(from keyData: Data, keyClass: CFString) -> SecKey? {
    let attributes: [CFString: Any] = [
      kSecAttrKeyType: kSecAttrKeyTypeRSA,
      kSecAttrKeyClass: keyClass,
    ]
    return SecKeyCreateWithData(keyData as CFData, attributes as CFDictionary, nil)
  }
}
