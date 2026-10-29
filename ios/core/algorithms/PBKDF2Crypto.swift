import Foundation
import CommonCrypto

package enum PBKDF2Crypto {
  package static func deriveKey(
    password passwordData: Data,
    salt saltData: Data,
    iterations: Int,
    keyLength: Int,
    hash: PBKDF2HashAlgorithm
  ) -> Data? {
    guard keyLength > 0, iterations > 0, let derivedKeyBytes = malloc(keyLength) else { return nil }
    let derivedKey = Data(bytesNoCopy: derivedKeyBytes, count: keyLength, deallocator: .free)
    let status = passwordData.withUnsafeBytes { passwordBytes in
      saltData.withUnsafeBytes { saltBytes in
        CCKeyDerivationPBKDF(
          CCPBKDFAlgorithm(kCCPBKDF2),
          passwordBytes.bindMemory(to: CChar.self).baseAddress,
          passwordData.count,
          saltBytes.bindMemory(to: UInt8.self).baseAddress,
          saltData.count,
          hash.pseudoRandomAlgorithm,
          UInt32(truncatingIfNeeded: iterations),
          derivedKeyBytes.assumingMemoryBound(to: UInt8.self),
          keyLength
        )
      }
    }
    guard status == kCCSuccess else { return nil }
    return derivedKey
  }
}
