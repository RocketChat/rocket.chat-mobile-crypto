import Foundation
import CommonCrypto

package enum AESCBCCrypto {
  private static let initializationVectorLength = kCCBlockSizeAES128

  package static func encrypt(_ plaintext: String, key: Data) -> String? {
    guard let initializationVector = RandomGenerator.bytes(count: initializationVectorLength),
          let ciphertext = crypt(CCOperation(kCCEncrypt), input: Data(plaintext.utf8), key: key, initializationVector: initializationVector) else {
      return nil
    }
    return (initializationVector + ciphertext).base64EncodedString()
  }

  package static func decrypt(_ ivAndCiphertextBase64: String, key: Data) -> String? {
    guard let ivAndCiphertext = Data(base64Encoded: ivAndCiphertextBase64),
          ivAndCiphertext.count >= initializationVectorLength * 2 else {
      return nil
    }
    let initializationVector = ivAndCiphertext.prefix(initializationVectorLength)
    let ciphertext = ivAndCiphertext.dropFirst(initializationVectorLength)
    guard ciphertext.count % kCCBlockSizeAES128 == 0,
          let plaintext = crypt(CCOperation(kCCDecrypt), input: ciphertext, key: key, initializationVector: initializationVector) else {
      return nil
    }
    return String(data: plaintext, encoding: .utf8)
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
