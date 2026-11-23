import Foundation
import MobileCryptoCore
import NitroModules

final class HybridRSAPrivateKey: HybridRSAPrivateKeySpec {
  let key: SecKey

  init(key: SecKey) {
    self.key = key
    super.init()
  }

  var memorySize: Int {
    SecKeyGetBlockSize(key)
  }

  func exportJwk() throws -> String {
    try RSAJWKConverter.json(ofPrivateKey: key).orThrow("Key export failed")
  }
}
