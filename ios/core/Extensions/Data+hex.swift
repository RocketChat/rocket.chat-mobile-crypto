import Foundation

extension Data {
  package var lowercaseHexString: String {
    let hexDigits = Array("0123456789abcdef".utf8)
    var hexCharacters = [UInt8]()
    hexCharacters.reserveCapacity(count * 2)
    for byte in self {
      hexCharacters.append(hexDigits[Int(byte >> 4)])
      hexCharacters.append(hexDigits[Int(byte & 0x0F)])
    }
    return String(decoding: hexCharacters, as: UTF8.self)
  }
}
