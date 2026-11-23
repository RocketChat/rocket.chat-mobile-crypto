import Foundation

extension Data {
  package init?(canonicalBase64 base64: String) {
    guard let decoded = Data(base64Encoded: base64), decoded.base64EncodedString() == base64 else { return nil }
    self = decoded
  }

  package init?(base64URLEncoded base64URL: String) {
    var unpadded = Substring(base64URL)
    while unpadded.hasSuffix("=") {
      unpadded.removeLast()
    }
    let padding = String(repeating: "=", count: (4 - unpadded.utf8.count % 4) % 4)
    guard base64URL == unpadded || base64URL == unpadded + padding else { return nil }
    let base64 = unpadded
      .replacingOccurrences(of: "-", with: "+")
      .replacingOccurrences(of: "_", with: "/")
    guard let decoded = Data(base64Encoded: base64 + padding), decoded.base64URLEncodedString == unpadded else { return nil }
    self = decoded
  }

  package var base64URLEncodedString: String {
    base64EncodedString()
      .replacingOccurrences(of: "+", with: "-")
      .replacingOccurrences(of: "/", with: "_")
      .replacingOccurrences(of: "=", with: "")
  }
}
