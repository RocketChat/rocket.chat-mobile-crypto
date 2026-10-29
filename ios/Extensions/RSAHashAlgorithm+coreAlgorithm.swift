import MobileCryptoCore

extension RSAHashAlgorithm {
  var coreAlgorithm: MobileCryptoCore.RSAHashAlgorithm {
    switch self {
    case .raw:
      return .raw
    case .sha1:
      return .sha1
    case .sha224:
      return .sha224
    case .sha256:
      return .sha256
    case .sha384:
      return .sha384
    case .sha512:
      return .sha512
    }
  }
}
