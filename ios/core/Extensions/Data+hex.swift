import Foundation

extension Data {
  init?(hexString: String) {
    let hexCharacters = hexString.utf8.filter { $0 != UInt8(ascii: " ") }
    guard hexCharacters.count % 2 == 0 else { return nil }
    var bytes = [UInt8](repeating: 0, count: hexCharacters.count / 2)
    for byteIndex in bytes.indices {
      guard let highNibble = Self.nibble(fromHexCharacter: hexCharacters[byteIndex * 2]),
            let lowNibble = Self.nibble(fromHexCharacter: hexCharacters[byteIndex * 2 + 1]) else {
        return nil
      }
      bytes[byteIndex] = highNibble << 4 | lowNibble
    }
    self.init(bytes)
  }

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

  private static func nibble(fromHexCharacter character: UInt8) -> UInt8? {
    switch character {
    case UInt8(ascii: "0")...UInt8(ascii: "9"):
      return character - UInt8(ascii: "0")
    case UInt8(ascii: "a")...UInt8(ascii: "f"):
      return character - UInt8(ascii: "a") + 10
    case UInt8(ascii: "A")...UInt8(ascii: "F"):
      return character - UInt8(ascii: "A") + 10
    default:
      return nil
    }
  }
}
