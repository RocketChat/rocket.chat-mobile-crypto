import Foundation
import CommonCrypto

package enum AESCBCCrypto {
  package static func encrypt(_ plaintext: Data, key: Data, initializationVector: Data) -> Data? {
    crypt(CCOperation(kCCEncrypt), input: plaintext, key: key, initializationVector: initializationVector)
  }

  package static func decrypt(_ ciphertext: Data, key: Data, initializationVector: Data) -> Data? {
    guard !ciphertext.isEmpty, ciphertext.count % kCCBlockSizeAES128 == 0 else { return nil }
    return crypt(CCOperation(kCCDecrypt), input: ciphertext, key: key, initializationVector: initializationVector)
  }

  package static func encryptBase64(_ dataBase64: String, keyHex: String, ivHex: String) -> String? {
    cryptBase64(CCOperation(kCCEncrypt), dataBase64: dataBase64, keyHex: keyHex, ivHex: ivHex)
  }

  package static func decryptBase64(_ dataBase64: String, keyHex: String, ivHex: String) -> String? {
    cryptBase64(CCOperation(kCCDecrypt), dataBase64: dataBase64, keyHex: keyHex, ivHex: ivHex)
  }

  private static func cryptBase64(_ operation: CCOperation, dataBase64: String, keyHex: String, ivHex: String) -> String? {
    guard let input = Data(base64Encoded: dataBase64),
          let key = Data(hexString: keyHex),
          let initializationVector = Data(hexString: ivHex) else {
      return nil
    }
    return crypt(operation, input: input, key: key, initializationVector: initializationVector)?.base64EncodedString()
  }

  private static func crypt(_ operation: CCOperation, input: Data, key: Data, initializationVector: Data) -> Data? {
    guard initializationVector.count == kCCBlockSizeAES128 else { return nil }
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
    return output
  }
}
