import Foundation
import Security

package enum RSAJWKConverter {
  private static let keyType = "RSA"
  private static let algorithm = "RSA-OAEP-256"
  private static let privateKeyVersion = Data([0])
  private static let publicKeyIntegerCount = 2
  private static let privateKeyIntegerCount = 9
  private static let componentNames = ["n", "e", "d", "p", "q", "dp", "dq", "qi"]

  package static func privateKey(fromJson json: String) -> SecKey? {
    guard let jwk = decode(json),
          let integers = decodedIntegers([jwk.n, jwk.e, jwk.d, jwk.p, jwk.q, jwk.dp, jwk.dq, jwk.qi]) else {
      return nil
    }
    return key(from: ASN1DER.sequence(ofIntegers: [privateKeyVersion] + integers), keyClass: kSecAttrKeyClassPrivate)
  }

  package static func publicKey(fromJson json: String) -> SecKey? {
    guard let jwk = decode(json), let integers = decodedIntegers([jwk.n, jwk.e]) else { return nil }
    return key(from: ASN1DER.sequence(ofIntegers: integers), keyClass: kSecAttrKeyClassPublic)
  }

  private static func decodedIntegers(_ encodedIntegers: [String?]) -> [Data]? {
    let integers = encodedIntegers.compactMap { $0.flatMap(Data.init(base64URLEncoded:)) }
    return integers.count == encodedIntegers.count ? integers : nil
  }

  package static func json(ofPrivateKey key: SecKey) -> String? {
    integers(of: key, count: privateKeyIntegerCount)
      .map { json(keyOperation: "decrypt", integers: Array($0.dropFirst())) }
  }

  package static func json(ofPublicKey key: SecKey) -> String? {
    integers(of: key, count: publicKeyIntegerCount)
      .map { json(keyOperation: "encrypt", integers: $0) }
  }

  private static func decode(_ json: String) -> JWK? {
    guard let jwk = try? JSONDecoder().decode(JWK.self, from: Data(json.utf8)), jwk.kty == keyType else { return nil }
    return jwk
  }

  private static func integers(of key: SecKey, count: Int) -> [Data]? {
    (SecKeyCopyExternalRepresentation(key, nil) as Data?).flatMap { ASN1DER.integers(inSequence: $0, count: count) }
  }

  private static func key(from keyData: Data, keyClass: CFString) -> SecKey? {
    let attributes: [CFString: Any] = [
      kSecAttrKeyType: kSecAttrKeyTypeRSA,
      kSecAttrKeyClass: keyClass,
    ]
    return SecKeyCreateWithData(keyData as CFData, attributes as CFDictionary, nil)
  }

  private static func json(keyOperation: String, integers: [Data]) -> String {
    let header = "\"kty\":\"\(keyType)\",\"alg\":\"\(algorithm)\",\"ext\":true,\"key_ops\":[\"\(keyOperation)\"]"
    let components = zip(componentNames, integers).map { "\"\($0)\":\"\($1.base64URLEncodedString)\"" }
    return "{\(([header] + components).joined(separator: ","))}"
  }
}
