import Foundation
import NitroModules

extension HybridAESKeySpec_protocol {
  func keyData() throws -> Data {
    try (self as? HybridAESKey).orThrow("Expected an AESKey created by this module").data
  }
}
