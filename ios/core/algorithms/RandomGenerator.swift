import Foundation
import Security

package enum RandomGenerator {
  package static func uuid() -> String {
    UUID().uuidString
  }

  package static func bytes(count: Int) -> Data? {
    guard count > 0 else { return Data() }
    guard let buffer = malloc(count) else { return nil }
    guard SecRandomCopyBytes(kSecRandomDefault, count, buffer) == errSecSuccess else {
      free(buffer)
      return nil
    }
    return Data(bytesNoCopy: buffer, count: count, deallocator: .free)
  }
}
