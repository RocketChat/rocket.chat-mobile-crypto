import Foundation
import MobileCryptoCore
import NitroModules

extension HybridAESKeySpec_protocol {
  func aesKey() throws -> AESKey {
    try (self as? HybridAESKey).orThrow("Expected an AESKey created by this module").key
  }
}
