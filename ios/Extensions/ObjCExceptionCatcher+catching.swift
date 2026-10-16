import NitroModules

extension ObjCExceptionCatcher {
  static func catching<Value>(_ body: () -> Value) throws -> Value {
    var value: Value?
    if let reason = exceptionReason(during: { value = body() }) {
      throw RuntimeError.error(withMessage: reason)
    }
    return value!
  }
}
