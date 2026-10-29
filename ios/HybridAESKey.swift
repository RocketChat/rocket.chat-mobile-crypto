import Foundation
import MobileCryptoCore
import NitroModules

final class HybridAESKey: HybridAESKeySpec {
  let data: Data

  init(data: Data) {
    self.data = data
    super.init()
  }

  var memorySize: Int {
    data.count
  }

  func exportBase64Url() throws -> String {
    data.base64URLEncodedString
  }
}
