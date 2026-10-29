import MobileCryptoCore

extension SHAAlgorithm {
  var coreAlgorithm: MobileCryptoCore.SHAAlgorithm {
    switch self {
    case .sha1:
      return .sha1
    case .sha256:
      return .sha256
    case .sha384:
      return .sha384
    case .sha512:
      return .sha512
    }
  }
}
