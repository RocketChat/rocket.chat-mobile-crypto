import Foundation
import Security

package enum RandomGenerator {
  private static let alphanumericCharacters = Array("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz".utf8)

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

  package static func alphanumeric(length: Int) -> String? {
    guard length > 0 else { return "" }
    guard let buffer = malloc(length)?.bindMemory(to: UInt8.self, capacity: length) else { return nil }
    defer { free(buffer) }
    let characterCount = UInt32(alphanumericCharacters.count)
    for index in 0..<length {
      buffer[index] = alphanumericCharacters[Int(arc4random_uniform(characterCount))]
    }
    return String(decoding: UnsafeBufferPointer(start: buffer, count: length), as: UTF8.self)
  }
}
