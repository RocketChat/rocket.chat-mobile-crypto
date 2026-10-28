import NitroModules

extension Double {
  func toCount() throws -> Int {
    guard self >= 0, let count = Int(exactly: rounded(.towardZero)) else {
      throw RuntimeError.error(withMessage: "Expected a non-negative count, got \(self)")
    }
    return count
  }
}
