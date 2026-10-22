import Foundation
import CommonCrypto

enum AESCBCCrypto {
  static func encryptBase64(_ dataBase64: String, keyHex: String, ivHex: String) -> String? {
    crypt(CCOperation(kCCEncrypt), dataBase64: dataBase64, keyHex: keyHex, ivHex: ivHex)
  }

  static func decryptBase64(_ dataBase64: String, keyHex: String, ivHex: String) -> String? {
    crypt(CCOperation(kCCDecrypt), dataBase64: dataBase64, keyHex: keyHex, ivHex: ivHex)
  }

  private static func crypt(_ operation: CCOperation, dataBase64: String, keyHex: String, ivHex: String) -> String? {
    guard let input = Data(base64Encoded: dataBase64),
          let key = Data(hexString: keyHex),
          let initializationVector = Data(hexString: ivHex),
          initializationVector.count == kCCBlockSizeAES128 else {
      return nil
    }
    var output = Data(count: input.count + kCCBlockSizeAES128)
    let outputCapacity = output.count
    var outputLength = 0
    let status = output.withUnsafeMutableBytes { outputBytes in
      input.withUnsafeBytes { inputBytes in
        key.withUnsafeBytes { keyBytes in
          initializationVector.withUnsafeBytes { initializationVectorBytes in
            CCCrypt(
              operation,
              CCAlgorithm(kCCAlgorithmAES128),
              CCOptions(kCCOptionPKCS7Padding),
              keyBytes.baseAddress,
              key.count,
              initializationVectorBytes.baseAddress,
              inputBytes.baseAddress,
              input.count,
              outputBytes.baseAddress,
              outputCapacity,
              &outputLength
            )
          }
        }
      }
    }
    guard status == kCCSuccess else { return nil }
    output.count = outputLength
    return output.base64EncodedString()
  }
}
