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

  func decrypt(ciphertext: ArrayBuffer) throws -> Promise<ArrayBuffer> {
    let ciphertextData = ArrayBuffer.copy(of: ciphertext).toData(copyIfNeeded: true)
    return Promise.parallel { [key] in
      ArrayBuffer.copying(try RSACrypto.decrypt(ciphertextData, using: key).orThrow("Decryption failed"))
    }
  }

  func sign(message: ArrayBuffer, hash: RSAHashAlgorithm) throws -> Promise<ArrayBuffer> {
    let messageData = ArrayBuffer.copy(of: message).toData(copyIfNeeded: true)
    return Promise.parallel { [key] in
      ArrayBuffer.copying(try RSACrypto.sign(messageData, using: key, hash: hash.coreAlgorithm).orThrow("Signing failed"))
    }
  }
}
