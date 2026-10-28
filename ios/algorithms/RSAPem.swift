import Foundation

enum RSAPem {
  private static let parseTags = ["RSA PRIVATE", "RSA PUBLIC", "PRIVATE", "PUBLIC"]

  static func format(_ keyData: Data, tag: String) -> String {
    let body = keyData.base64EncodedString(options: .lineLength64Characters)
    return "\(header(tag))\n\(body)\n\(footer(tag))"
  }

  static func parse(_ pem: String) -> Data? {
    for tag in parseTags {
      guard let headerRange = pem.range(of: header(tag)),
            let footerRange = pem.range(of: footer(tag)) else {
        continue
      }
      guard headerRange.upperBound <= footerRange.lowerBound else { return nil }
      let body = pem[headerRange.upperBound..<footerRange.lowerBound]
        .replacingOccurrences(of: "\n", with: "")
        .replacingOccurrences(of: "\r", with: "")
        .trimmingCharacters(in: .whitespacesAndNewlines)
      return Data(base64Encoded: body, options: .ignoreUnknownCharacters)
    }
    return Data(base64Encoded: pem, options: .ignoreUnknownCharacters)
  }

  private static func header(_ tag: String) -> String {
    "-----BEGIN \(tag) KEY-----"
  }

  private static func footer(_ tag: String) -> String {
    "-----END \(tag) KEY-----"
  }
}
