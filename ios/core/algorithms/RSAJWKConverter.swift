import Foundation
import Security

package enum RSAJWKConverter {
  private static let keyType = "RSA"
  private static let algorithm = "RSA-OAEP-256"
  private static let privateKeyVersion = Data([0])
  private static let publicKeyIntegerCount = 2
  private static let privateKeyIntegerCount = 9

  package static func privateKey(fromJson json: String) -> SecKey? {
    guard let jwk = decode(json),
          let modulus = Data(base64URLEncoded: jwk.n),
          let publicExponent = Data(base64URLEncoded: jwk.e) else {
      return nil
    }
    let encodedPrivateComponents = [jwk.d, jwk.p, jwk.q, jwk.dp, jwk.dq, jwk.qi]
    let privateComponents = encodedPrivateComponents.compactMap { $0.flatMap(Data.init(base64URLEncoded:)) }
    guard privateComponents.count == encodedPrivateComponents.count else { return nil }
    let integers = [privateKeyVersion, modulus, publicExponent] + privateComponents
    return RSAKeyLoader.key(from: ASN1DER.sequence(ofIntegers: integers), keyClass: kSecAttrKeyClassPrivate)
  }

  package static func publicKey(fromJson json: String) -> SecKey? {
    guard let jwk = decode(json),
          let modulus = Data(base64URLEncoded: jwk.n),
          let publicExponent = Data(base64URLEncoded: jwk.e) else {
      return nil
    }
    return RSAKeyLoader.key(from: ASN1DER.sequence(ofIntegers: [modulus, publicExponent]), keyClass: kSecAttrKeyClassPublic)
  }

  package static func json(ofPrivateKey key: SecKey) -> String? {
    integers(of: key, count: privateKeyIntegerCount)
      .map { makeJWK(keyOperation: "decrypt", integers: Array($0.dropFirst())).json }
  }

  package static func json(ofPublicKey key: SecKey) -> String? {
    integers(of: key, count: publicKeyIntegerCount)
      .map { makeJWK(keyOperation: "encrypt", integers: $0).json }
  }

  private static func decode(_ json: String) -> JWK? {
    guard let jwk = try? JSONDecoder().decode(JWK.self, from: Data(json.utf8)), jwk.kty == keyType else { return nil }
    return jwk
  }

  private static func integers(of key: SecKey, count: Int) -> [Data]? {
    RSACrypto.externalRepresentation(of: key).flatMap { ASN1DER.integers(inSequence: $0, count: count) }
  }

  private static func makeJWK(keyOperation: String, integers: [Data]) -> JWK {
    let components = integers.map(\.base64URLEncodedString)
    let component = { (index: Int) -> String? in components.indices.contains(index) ? components[index] : nil }
    return JWK(
      kty: keyType,
      alg: algorithm,
      ext: true,
      keyOperations: [keyOperation],
      n: components[0],
      e: components[1],
      d: component(2),
      p: component(3),
      q: component(4),
      dp: component(5),
      dq: component(6),
      qi: component(7)
    )
  }
}
