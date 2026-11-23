import Foundation
import CommonCrypto

package enum AESCBCCrypto {
  private static let initializationVectorLength = kCCBlockSizeAES128
  private static let withoutPadding = CCOptions(0)

  package static func encrypt(_ plaintext: String, key: AESKey) -> String? {
    guard let initializationVector = RandomGenerator.bytes(count: initializationVectorLength),
          let ciphertext = crypt(CCOperation(kCCEncrypt), CCOptions(kCCOptionPKCS7Padding), input: Data(plaintext.utf8), key: key, initializationVector: initializationVector) else {
      return nil
    }
    return (initializationVector + ciphertext).base64EncodedString()
  }

  package static func decrypt(_ ivAndCiphertextBase64: String, key: AESKey) -> String? {
    guard let ivAndCiphertext = Data(canonicalBase64: ivAndCiphertextBase64),
          ivAndCiphertext.count >= initializationVectorLength * 2 else {
      return nil
    }
    let initializationVector = ivAndCiphertext.prefix(initializationVectorLength)
    let ciphertext = ivAndCiphertext.dropFirst(initializationVectorLength)
    guard ciphertext.count % kCCBlockSizeAES128 == 0,
          let paddedPlaintext = crypt(CCOperation(kCCDecrypt), withoutPadding, input: ciphertext, key: key, initializationVector: initializationVector),
          let plaintext = removingPKCS7Padding(paddedPlaintext) else {
      return nil
    }
    return String(strictUTF8: plaintext)
  }

  private static func removingPKCS7Padding(_ paddedPlaintext: Data) -> Data? {
    guard let padLength = paddedPlaintext.last.map(Int.init),
          (1...kCCBlockSizeAES128).contains(padLength),
          paddedPlaintext.suffix(padLength).allSatisfy({ Int($0) == padLength }) else {
      return nil
    }
    return paddedPlaintext.dropLast(padLength)
  }

  private static func crypt(_ operation: CCOperation, _ options: CCOptions, input: Data, key: AESKey, initializationVector: Data) -> Data? {
    var output = Data(count: input.count + kCCBlockSizeAES128)
    let outputCapacity = output.count
    var outputLength = 0
    let status = output.withUnsafeMutableBytes { outputBytes in
      input.withUnsafeBytes { inputBytes in
        key.data.withUnsafeBytes { keyBytes in
          initializationVector.withUnsafeBytes { initializationVectorBytes in
            CCCrypt(
              operation,
              CCAlgorithm(kCCAlgorithmAES128),
              options,
              keyBytes.baseAddress,
              key.data.count,
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
