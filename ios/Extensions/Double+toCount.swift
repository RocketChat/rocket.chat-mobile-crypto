import NitroModules

extension Double {
  func toCount() throws -> Int {
    guard self >= 0, let count = Int32(exactly: rounded(.towardZero)) else {
      throw RuntimeError.error(withMessage: "Expected a count from 0 to \(Int32.max), got \(self)")
    }
    return Int(count)
  }
}
