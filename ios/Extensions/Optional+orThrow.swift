import NitroModules

extension Optional {
  func orThrow(_ message: String) throws -> Wrapped {
    guard let self else {
      throw RuntimeError.error(withMessage: message)
    }
    return self
  }
}
