import CryptoKit
import Foundation

extension SHAAlgorithm {
  package func digest(of input: Data) -> Data {
    switch self {
    case .sha1:
      return Data(Insecure.SHA1.hash(data: input))
    case .sha256:
      return Data(SHA256.hash(data: input))
    case .sha384:
      return Data(SHA384.hash(data: input))
    case .sha512:
      return Data(SHA512.hash(data: input))
    }
  }
}
