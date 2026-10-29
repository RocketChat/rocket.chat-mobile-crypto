import Foundation

enum RSAPem {
  enum Tag: String, CaseIterable {
    case rsaPrivate = "RSA PRIVATE"
    case rsaPublic = "RSA PUBLIC"
    case privateKey = "PRIVATE"
    case publicKey = "PUBLIC"
  }

  struct Block {
    let tag: Tag?
    let data: Data
  }

  static func format(_ keyData: Data, tag: Tag) -> String {
    let body = keyData.base64EncodedString(options: .lineLength64Characters)
    return "\(header(tag))\n\(body)\n\(footer(tag))"
  }

  static func parse(_ pem: String) -> Block? {
    for tag in Tag.allCases {
      guard let headerRange = pem.range(of: header(tag)),
            let footerRange = pem.range(of: footer(tag)) else {
        continue
      }
      guard headerRange.upperBound <= footerRange.lowerBound else { return nil }
      let body = pem[headerRange.upperBound..<footerRange.lowerBound]
        .replacingOccurrences(of: "\n", with: "")
        .replacingOccurrences(of: "\r", with: "")
        .trimmingCharacters(in: .whitespacesAndNewlines)
      return Data(base64Encoded: body, options: .ignoreUnknownCharacters).map { Block(tag: tag, data: $0) }
    }
    return Data(base64Encoded: pem, options: .ignoreUnknownCharacters).map { Block(tag: nil, data: $0) }
  }

  private static func header(_ tag: Tag) -> String {
    "-----BEGIN \(tag.rawValue) KEY-----"
  }

  private static func footer(_ tag: Tag) -> String {
    "-----END \(tag.rawValue) KEY-----"
  }
}
