import Foundation
import MobileCryptoCore
import NitroModules

final class HybridRSAPublicKey: HybridRSAPublicKeySpec {
  let key: SecKey

  init(key: SecKey) {
    self.key = key
    super.init()
  }

  var memorySize: Int {
    SecKeyGetBlockSize(key)
  }

  func exportJwk() throws -> String {
    try RSAJWKConverter.json(ofPublicKey: key).orThrow("Key export failed")
  }
}
