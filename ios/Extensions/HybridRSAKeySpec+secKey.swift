import Foundation
import NitroModules

extension HybridRSAPrivateKeySpec_protocol {
  func secKey() throws -> SecKey {
    try (self as? HybridRSAPrivateKey).orThrow("Expected an RSAPrivateKey created by this module").key
  }
}

extension HybridRSAPublicKeySpec_protocol {
  func secKey() throws -> SecKey {
    try (self as? HybridRSAPublicKey).orThrow("Expected an RSAPublicKey created by this module").key
  }
}
