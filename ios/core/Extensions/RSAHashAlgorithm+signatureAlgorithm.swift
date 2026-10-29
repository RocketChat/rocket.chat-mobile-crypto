import Security

extension RSAHashAlgorithm {
  var signatureAlgorithm: SecKeyAlgorithm {
    switch self {
    case .raw:
      return .rsaSignatureDigestPKCS1v15Raw
    case .sha1:
      return .rsaSignatureMessagePKCS1v15SHA1
    case .sha224:
      return .rsaSignatureMessagePKCS1v15SHA224
    case .sha256:
      return .rsaSignatureMessagePKCS1v15SHA256
    case .sha384:
      return .rsaSignatureMessagePKCS1v15SHA384
    case .sha512:
      return .rsaSignatureMessagePKCS1v15SHA512
    }
  }
}
