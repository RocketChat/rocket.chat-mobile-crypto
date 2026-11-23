import Foundation

extension String {
  package init?(strictUTF8 data: Data) {
    let decoded = String(decoding: data, as: UTF8.self)
    guard decoded.utf8.elementsEqual(data) else { return nil }
    self = decoded
  }
}
