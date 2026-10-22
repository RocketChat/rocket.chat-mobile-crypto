import Foundation
import CryptoKit

enum SHACrypto {
  static func hashBase64(_ dataBase64: String, algorithm: String) -> String? {
    guard let input = Data(base64Encoded: dataBase64) else { return nil }
    return digest(of: input, algorithm: algorithm)?.base64EncodedString()
  }

  static func hashUtf8ToHex(_ text: String, algorithm: String) -> String? {
    digest(of: Data(text.utf8), algorithm: algorithm)?.lowercaseHexString
  }

  private static func digest(of input: Data, algorithm: String) -> Data? {
    switch algorithm {
    case "SHA-1":
      return Data(Insecure.SHA1.hash(data: input))
    case "SHA-256":
      return Data(SHA256.hash(data: input))
    case "SHA-384":
      return Data(SHA384.hash(data: input))
    case "SHA-512":
      return Data(SHA512.hash(data: input))
    default:
      return nil
    }
  }
}
