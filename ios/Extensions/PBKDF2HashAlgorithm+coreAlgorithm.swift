import MobileCryptoCore

extension PBKDF2HashAlgorithm {
  var coreAlgorithm: MobileCryptoCore.PBKDF2HashAlgorithm {
    switch self {
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
