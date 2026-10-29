import Foundation

package enum SHACrypto {
  package static func hashBase64(_ dataBase64: String, algorithm: SHAAlgorithm) -> String? {
    guard let input = Data(base64Encoded: dataBase64) else { return nil }
    return algorithm.digest(of: input).base64EncodedString()
  }

  package static func hashUtf8ToHex(_ text: String, algorithm: SHAAlgorithm) -> String {
    algorithm.digest(of: Data(text.utf8)).lowercaseHexString
  }
}
