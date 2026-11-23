import Foundation
import MobileCryptoCore
import NitroModules

final class HybridRSAPublicKey: HybridRSAPublicKeySpec {
  private let key: SecKey

  init(key: SecKey) {
    self.key = key
    super.init()
  }

  var memorySize: Int {
    SecKeyGetBlockSize(key)
  }

  func encrypt(plaintext: String) throws -> String {
    try RSACrypto.encrypt(plaintext, using: key).orThrow("Encryption failed")
  }

  func verify(signature: ArrayBuffer, message: ArrayBuffer, hash: RSAHashAlgorithm) throws -> Bool {
    RSACrypto.verify(signature.toData(copyIfNeeded: true), message: message.toData(copyIfNeeded: true), using: key, hash: hash.coreAlgorithm)
  }

  func exportJwk() throws -> String {
    try RSAJWKConverter.json(ofPublicKey: key).orThrow("Key export failed")
  }
}
