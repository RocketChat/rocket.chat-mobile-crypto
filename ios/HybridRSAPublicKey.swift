import Foundation
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

  func encrypt(plaintext: ArrayBuffer) throws -> ArrayBuffer {
    ArrayBuffer.copying(try RSACrypto.encrypt(plaintext.copiedData(), using: key).orThrow("Encryption failed"))
  }

  func verify(signature: ArrayBuffer, message: ArrayBuffer, hash: RSAHashAlgorithm) throws -> Bool {
    RSACrypto.verify(signature.copiedData(), message: message.copiedData(), using: key, hash: hash)
  }
}
