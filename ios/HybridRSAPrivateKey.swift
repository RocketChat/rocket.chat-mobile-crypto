import Foundation
import MobileCryptoCore
import NitroModules

final class HybridRSAPrivateKey: HybridRSAPrivateKeySpec {
  private let key: SecKey

  init(key: SecKey) {
    self.key = key
    super.init()
  }

  var memorySize: Int {
    SecKeyGetBlockSize(key)
  }

  func decrypt(ciphertext: String) throws -> Promise<String> {
    return Promise.parallel { [key] in
      try RSACrypto.decrypt(ciphertext, using: key).orThrow("Decryption failed")
    }
  }

  func sign(message: ArrayBuffer, hash: RSAHashAlgorithm) throws -> Promise<ArrayBuffer> {
    let messageData = message.copiedData()
    return Promise.parallel { [key] in
      ArrayBuffer.copying(try RSACrypto.sign(messageData, using: key, hash: hash.coreAlgorithm).orThrow("Signing failed"))
    }
  }

  func exportJwk() throws -> String {
    try RSAJWKConverter.json(ofPrivateKey: key).orThrow("Key export failed")
  }
}
