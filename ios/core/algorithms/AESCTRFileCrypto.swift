import Foundation
import CommonCrypto
import CryptoKit

package enum AESCTRFileCrypto {
  private static let chunkSize = 65536
  private static let outputFilePrefix = "processed_"
  private static let fileScheme = "file://"
  private static let keyLength = 32

  package static func encryptFile(_ filePath: String) -> EncryptedFile? {
    let inputPath = filePath.normalizedFilePath
    guard let key = RandomGenerator.bytes(count: keyLength),
          let initializationVector = RandomGenerator.bytes(count: kCCBlockSizeAES128) else {
      return nil
    }
    let outputPath = outputPath(for: inputPath)
    guard let plaintextDigest = transform(
      inputPath: inputPath,
      outputPath: outputPath,
      operation: CCOperation(kCCEncrypt),
      key: key,
      initializationVector: initializationVector
    ) else {
      try? FileManager.default.removeItem(atPath: outputPath)
      return nil
    }
    return EncryptedFile(
      path: fileScheme + outputPath,
      key: key.base64URLEncodedString,
      iv: initializationVector.base64EncodedString(),
      sha256: plaintextDigest.lowercaseHexString
    )
  }

  package static func decryptFile(_ filePath: String, base64URLKey: String, base64InitializationVector: String, sha256: String) -> String? {
    let inputPath = filePath.normalizedFilePath
    guard let key = Data(base64URLEncoded: base64URLKey),
          let initializationVector = Data(base64Encoded: base64InitializationVector),
          initializationVector.count == kCCBlockSizeAES128 else {
      return nil
    }
    let outputPath = outputPath(for: inputPath)
    guard let plaintextDigest = transform(
      inputPath: inputPath,
      outputPath: outputPath,
      operation: CCOperation(kCCDecrypt),
      key: key,
      initializationVector: initializationVector
    ),
      plaintextDigest.lowercaseHexString == sha256.lowercased() else {
      try? FileManager.default.removeItem(atPath: outputPath)
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
    return fileScheme + inputPath
  }

  private static func outputPath(for inputPath: String) -> String {
    let inputPathString = inputPath as NSString
    return (inputPathString.deletingLastPathComponent as NSString)
      .appendingPathComponent("\(outputFilePrefix)\(UUID().uuidString)")
  }

  private static func transform(
    inputPath: String,
    outputPath: String,
    operation: CCOperation,
    key: Data,
    initializationVector: Data
  ) -> Data? {
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
    guard creationStatus == kCCSuccess, let cryptor else { return nil }
    defer { CCCryptorRelease(cryptor) }

    guard let input = FileHandle(forReadingAtPath: inputPath),
          FileManager.default.createFile(atPath: outputPath, contents: nil),
          let output = FileHandle(forWritingAtPath: outputPath) else {
      return nil
    }
    defer {
      input.closeFile()
      output.closeFile()
    }

    let isEncrypting = operation == CCOperation(kCCEncrypt)
    var plaintextHasher = SHA256()
    var outputBuffer = [UInt8](repeating: 0, count: chunkSize)
    do {
      while let chunk = try autoreleasepool(invoking: { try input.read(upToCount: chunkSize) }), !chunk.isEmpty {
        var bytesMoved = 0
        let updateStatus = chunk.withUnsafeBytes { chunkBytes in
          CCCryptorUpdate(cryptor, chunkBytes.baseAddress, chunk.count, &outputBuffer, chunkSize, &bytesMoved)
        }
        guard updateStatus == kCCSuccess else { return nil }
        let outputChunk = outputBuffer[..<bytesMoved]
        if isEncrypting {
          plaintextHasher.update(data: chunk)
        } else {
          plaintextHasher.update(data: outputChunk)
        }
        try output.write(contentsOf: outputChunk)
      }
      var finalBytesMoved = 0
      guard CCCryptorFinal(cryptor, &outputBuffer, chunkSize, &finalBytesMoved) == kCCSuccess else { return nil }
      let finalChunk = outputBuffer[..<finalBytesMoved]
      if !isEncrypting {
        plaintextHasher.update(data: finalChunk)
      }
      try output.write(contentsOf: finalChunk)
      return Data(plaintextHasher.finalize())
    } catch {
      return nil
    }
  }
}
