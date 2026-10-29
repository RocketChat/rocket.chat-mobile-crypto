import Foundation
import Security

package enum RandomGenerator {
  private static let alphanumericCharacters = Array("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")

  package static func uuid() -> String {
    UUID().uuidString
  }

  package static func bytes(count: Int) -> Data? {
    guard count > 0 else { return Data() }
    var randomBytes = Data(count: count)
    let status = randomBytes.withUnsafeMutableBytes { buffer in
      SecRandomCopyBytes(kSecRandomDefault, count, buffer.baseAddress!)
    }
    return status == errSecSuccess ? randomBytes : nil
  }

  package static func alphanumeric(length: Int) -> String {
    let characterCount = UInt32(alphanumericCharacters.count)
    return String((0..<length).map { _ in alphanumericCharacters[Int(arc4random_uniform(characterCount))] })
  }
}
