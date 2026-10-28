import Foundation
import CommonCrypto

enum AESCTRFileCrypto {
  private static let chunkSize = 65536
  private static let outputFilePrefix = "processed_"

  static func encryptFile(_ filePath: String, base64URLKey: String, base64InitializationVector: String) -> String? {
    processFile(filePath, operation: CCOperation(kCCEncrypt), base64URLKey: base64URLKey, base64InitializationVector: base64InitializationVector)
  }

  static func decryptFile(_ filePath: String, base64URLKey: String, base64InitializationVector: String) -> String? {
    processFile(filePath, operation: CCOperation(kCCDecrypt), base64URLKey: base64URLKey, base64InitializationVector: base64InitializationVector)
  }

  private static func processFile(
    _ filePath: String,
    operation: CCOperation,
    base64URLKey: String,
    base64InitializationVector: String
  ) -> String? {
    let inputPath = filePath.normalizedFilePath
    let fileManager = FileManager.default
    guard let key = Data(base64URLEncoded: base64URLKey),
          let initializationVector = Data(base64Encoded: base64InitializationVector),
          initializationVector.count == kCCBlockSizeAES128,
          fileManager.fileExists(atPath: inputPath) else {
      return nil
    }
    let inputPathString = inputPath as NSString
    let outputPath = (inputPathString.deletingLastPathComponent as NSString)
      .appendingPathComponent("\(outputFilePrefix)\(UUID().uuidString)_\(inputPathString.lastPathComponent)")

    guard transform(inputPath: inputPath, outputPath: outputPath, operation: operation, key: key, initializationVector: initializationVector) else {
      try? fileManager.removeItem(atPath: outputPath)
      return nil
    }
    guard operation == CCOperation(kCCDecrypt) else {
      return "file://\(outputPath)"
    }
    do {
      _ = try fileManager.replaceItemAt(
        URL(fileURLWithPath: inputPath),
        withItemAt: URL(fileURLWithPath: outputPath),
        backupItemName: nil,
        options: .usingNewMetadataOnly
      )
    } catch {
      try? fileManager.removeItem(atPath: outputPath)
      return nil
    }
    return "file://\(inputPath)"
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
      while let chunk = try input.read(upToCount: chunkSize), !chunk.isEmpty {
        var bytesMoved = 0
        let updateStatus = chunk.withUnsafeBytes { chunkBytes in
          CCCryptorUpdate(cryptor, chunkBytes.baseAddress, chunk.count, &outputBuffer, chunkSize, &bytesMoved)
        }
        guard updateStatus == kCCSuccess else { return false }
        try output.write(contentsOf: outputBuffer[..<bytesMoved])
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
