import Foundation
import Security

package enum RSAKeyLoader {
  private static let cache: NSCache<NSString, SecKey> = {
    let cache = NSCache<NSString, SecKey>()
    cache.countLimit = 16
    return cache
  }()

  package static func publicKey(fromPem pem: String) -> SecKey? {
    key(fromPem: pem, keyClass: kSecAttrKeyClassPublic, cachePrefix: "public:")
  }

  package static func privateKey(fromPem pem: String) -> SecKey? {
    key(fromPem: pem, keyClass: kSecAttrKeyClassPrivate, cachePrefix: "private:")
  }

  private static func key(fromPem pem: String, keyClass: CFString, cachePrefix: String) -> SecKey? {
    let cacheKey = (cachePrefix + pem) as NSString
    if let cachedKey = cache.object(forKey: cacheKey) {
      return cachedKey
    }
    guard let keyData = RSAPem.parse(pem)?.data,
          let key = key(from: keyData, keyClass: keyClass) else { return nil }
    cache.setObject(key, forKey: cacheKey)
    return key
  }

  package static func key(from keyData: Data, keyClass: CFString) -> SecKey? {
    let attributes: [CFString: Any] = [
      kSecAttrKeyType: kSecAttrKeyTypeRSA,
      kSecAttrKeyClass: keyClass,
    ]
    return SecKeyCreateWithData(keyData as CFData, attributes as CFDictionary, nil)
  }
}
