import Foundation
import MobileCryptoCore
import NitroModules

final class HybridAESKey: HybridAESKeySpec {
  let key: AESKey

  init(key: AESKey) {
    self.key = key
    super.init()
  }

  var memorySize: Int {
    key.data.count
  }

  func exportBase64Url() throws -> String {
    key.base64URL
  }
}
