import Foundation
import CommonCrypto

package enum AESCTRFileCrypto {
  private static let chunkSize = 65536
  private static let outputFilePrefix = "processed_"

  private struct CryptorUpdateError: Error {}

  package static func encryptFile(_ filePath: String, base64URLKey: String, base64InitializationVector: String) -> String? {
    processFile(filePath.normalizedFilePath, operation: CCOperation(kCCEncrypt), base64URLKey: base64URLKey, base64InitializationVector: base64InitializationVector)
      .map { "file://\($0)" }
  }

  package static func decryptFile(_ filePath: String, base64URLKey: String, base64InitializationVector: String) -> String? {
    let inputPath = filePath.normalizedFilePath
    guard let outputPath = processFile(inputPath, operation: CCOperation(kCCDecrypt), base64URLKey: base64URLKey, base64InitializationVector: base64InitializationVector) else {
      return nil
    }
    do {
      _ = try FileManager.default.replaceItemAt(
        URL(fileURLWithPath: inputPath),
        withItemAt: URL(fileURLWithPath: outputPath),
        backupItemName: nil,
        options: .usingNewMetadataOnly
      )
    } catch {
      try? FileManager.default.removeItem(atPath: outputPath)
      return nil
    }
    return "file://\(inputPath)"
  }

  private static func processFile(
    _ inputPath: String,
    operation: CCOperation,
    base64URLKey: String,
    base64InitializationVector: String
  ) -> String? {
    guard let key = Data(base64URLEncoded: base64URLKey),
          let initializationVector = Data(base64Encoded: base64InitializationVector),
          initializationVector.count == kCCBlockSizeAES128 else {
      return nil
    }
    let inputPathString = inputPath as NSString
    let outputPath = (inputPathString.deletingLastPathComponent as NSString)
      .appendingPathComponent("\(outputFilePrefix)\(UUID().uuidString)")

    guard transform(inputPath: inputPath, outputPath: outputPath, operation: operation, key: key, initializationVector: initializationVector) else {
      try? FileManager.default.removeItem(atPath: outputPath)
      return nil
    }
    return outputPath
  }

  private static func transform(
    inputPath: String,
    outputPath: String,
    operation: CCOperation,
    key: Data,
    initializationVector: Data
  ) -> Bool {
    var cryptor: CCCryptorRef?
    let creationStatus = key.withUnsafeBytes { keyBytes in
      initializationVector.withUnsafeBytes { initializationVectorBytes in
        CCCryptorCreateWithMode(
          operation,
          CCMode(kCCModeCTR),
          CCAlgorithm(kCCAlgorithmAES),
          CCPadding(ccNoPadding),
          initializationVectorBytes.baseAddress,
          keyBytes.baseAddress,
          key.count,
          nil,
          0,
          0,
          CCModeOptions(kCCModeOptionCTR_BE),
          &cryptor
        )
      }
    }
    guard creationStatus == kCCSuccess, let cryptor else { return false }
    defer { CCCryptorRelease(cryptor) }

    guard let input = FileHandle(forReadingAtPath: inputPath),
          FileManager.default.createFile(atPath: outputPath, contents: nil),
          let output = FileHandle(forWritingAtPath: outputPath) else {
      return false
    }
    defer {
      input.closeFile()
      output.closeFile()
    }

    var outputBuffer = [UInt8](repeating: 0, count: chunkSize)
    do {
      var reachedEnd = false
      while !reachedEnd {
        reachedEnd = try autoreleasepool {
          guard let chunk = try input.read(upToCount: chunkSize), !chunk.isEmpty else { return true }
          var bytesMoved = 0
          let updateStatus = chunk.withUnsafeBytes { chunkBytes in
            CCCryptorUpdate(cryptor, chunkBytes.baseAddress, chunk.count, &outputBuffer, chunkSize, &bytesMoved)
          }
          guard updateStatus == kCCSuccess else { throw CryptorUpdateError() }
          try output.write(contentsOf: outputBuffer[..<bytesMoved])
          return false
        }
      }
      var finalBytesMoved = 0
      guard CCCryptorFinal(cryptor, &outputBuffer, chunkSize, &finalBytesMoved) == kCCSuccess else { return false }
      try output.write(contentsOf: outputBuffer[..<finalBytesMoved])
      return true
    } catch {
      return false
    }
  }
}
