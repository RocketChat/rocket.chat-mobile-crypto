import CommonCrypto

extension PBKDF2HashAlgorithm {
  var pseudoRandomAlgorithm: CCPseudoRandomAlgorithm {
    switch self {
    case .sha1:
      return CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA1)
    case .sha224:
      return CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA224)
    case .sha256:
      return CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256)
    case .sha384:
      return CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA384)
    case .sha512:
      return CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA512)
    }
  }
}
