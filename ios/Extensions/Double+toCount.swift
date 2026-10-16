import NitroModules

extension Double {
  func toCount() throws -> UInt {
    guard isFinite, self >= 0 else {
      throw RuntimeError.error(withMessage: "Expected a non-negative count, got \(self)")
    }
    return UInt(self)
  }
}
