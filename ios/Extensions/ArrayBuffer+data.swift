import Foundation
import NitroModules

extension ArrayBuffer {
  static func copying(_ data: Data) -> ArrayBuffer {
    data.withUnsafeBytes { bytes in
      guard let baseAddress = bytes.bindMemory(to: UInt8.self).baseAddress else {
        return ArrayBuffer.allocate(size: 0)
      }
      return ArrayBuffer.copy(of: baseAddress, size: bytes.count)
    }
  }
}
