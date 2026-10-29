import Foundation
import CryptoKit

package enum FileChecksum {
  private static let chunkSize = 65536

  package static func sha256Hex(ofFileAt filePath: String) -> String? {
    guard let input = FileHandle(forReadingAtPath: filePath.normalizedFilePath) else { return nil }
    defer { input.closeFile() }
    var hasher = SHA256()
    do {
      var reachedEnd = false
      while !reachedEnd {
        reachedEnd = try autoreleasepool {
          guard let chunk = try input.read(upToCount: chunkSize), !chunk.isEmpty else { return true }
          hasher.update(data: chunk)
          return false
        }
      }
    } catch {
      return nil
    }
    return Data(hasher.finalize()).lowercaseHexString
  }
}
