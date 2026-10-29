import Foundation

extension Data {
  package init?(base64URLEncoded base64URL: String) {
    let base64 = base64URL
      .replacingOccurrences(of: "-", with: "+")
      .replacingOccurrences(of: "_", with: "/")
    let paddingLength = (4 - base64.utf16.count % 4) % 4
    self.init(base64Encoded: base64 + String(repeating: "=", count: paddingLength))
  }

  package var base64URLEncodedString: String {
    base64EncodedString()
      .replacingOccurrences(of: "+", with: "-")
      .replacingOccurrences(of: "/", with: "_")
      .replacingOccurrences(of: "=", with: "")
  }
}
