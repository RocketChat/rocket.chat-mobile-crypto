import Foundation

enum ASN1DER {
  private static let integerTag: UInt8 = 0x02
  private static let sequenceTag: UInt8 = 0x30
  private static let longFormLengthFlag: UInt8 = 0x80

  static func sequence(ofIntegers integers: [Data]) -> Data {
    let contents = integers.reduce(into: Data()) { $0.append(integer($1)) }
    return Data([sequenceTag]) + length(contents.count) + contents
  }

  static func integers(inSequence encoded: Data, count: Int) -> [Data]? {
    let bytes = [UInt8](encoded)
    guard bytes.count >= 2, bytes[0] == sequenceTag else { return nil }
    let sequenceLengthByte = bytes[1]
    var offset = 2
    if sequenceLengthByte & longFormLengthFlag != 0 {
      offset += Int(sequenceLengthByte & ~longFormLengthFlag)
    }
    var integers = [Data]()
    for _ in 0..<count {
      guard let integer = readInteger(bytes, offset: &offset) else { return nil }
      integers.append(integer)
    }
    return integers
  }

  private static func integer(_ value: Data) -> Data {
    let needsSignPadding = (value.first ?? 0) & 0x80 != 0
    let content = needsSignPadding ? Data([0]) + value : value
    return Data([integerTag]) + length(content.count) + content
  }

  private static func length(_ length: Int) -> Data {
    guard length >= Int(longFormLengthFlag) else { return Data([UInt8(length)]) }
    var lengthBytes = [UInt8]()
    var remaining = length
    while remaining > 0 {
      lengthBytes.insert(UInt8(remaining & 0xFF), at: 0)
      remaining >>= 8
    }
    return Data([longFormLengthFlag | UInt8(lengthBytes.count)] + lengthBytes)
  }

  private static func readInteger(_ bytes: [UInt8], offset: inout Int) -> Data? {
    guard offset + 1 < bytes.count, bytes[offset] == integerTag else { return nil }
    let firstLengthByte = bytes[offset + 1]
    offset += 2
    var length = Int(firstLengthByte)
    if firstLengthByte & longFormLengthFlag != 0 {
      let lengthByteCount = Int(firstLengthByte & ~longFormLengthFlag)
      guard lengthByteCount > 0, lengthByteCount < MemoryLayout<Int>.size, offset + lengthByteCount <= bytes.count else { return nil }
      length = bytes[offset..<offset + lengthByteCount].reduce(0) { $0 << 8 | Int($1) }
      offset += lengthByteCount
    }
    guard length <= bytes.count - offset else { return nil }
    var value = bytes[offset..<offset + length]
    offset += length
    if value.count > 1, value.first == 0 {
      value = value.dropFirst()
    }
    return Data(value)
  }
}
