import Foundation
import Security

enum RSAJWKConverter {
  private static let keyType = "RSA"
  private static let algorithm = "RSA-OAEP-256"
  private static let privateKeyVersion = Data([0])

  static func pem(from jwk: JWK) -> String? {
    guard jwk.kty == keyType,
          let modulus = Data(base64URLEncoded: jwk.n),
          let publicExponent = Data(base64URLEncoded: jwk.e) else {
      return nil
    }
    guard let privateExponentBase64URL = jwk.d, !privateExponentBase64URL.isEmpty else {
      return RSAPem.format(ASN1DER.sequence(ofIntegers: [modulus, publicExponent]), tag: .rsaPublic)
    }
    let privateComponents = [privateExponentBase64URL, jwk.p, jwk.q, jwk.dp, jwk.dq, jwk.qi]
      .map { $0.flatMap(Data.init(base64URLEncoded:)) }
    guard privateComponents.allSatisfy({ $0 != nil }) else { return nil }
    let integers = [privateKeyVersion, modulus, publicExponent] + privateComponents.compactMap { $0 }
    return RSAPem.format(ASN1DER.sequence(ofIntegers: integers), tag: .rsaPrivate)
  }

  static func jwk(fromPem pem: String) -> JWK? {
    guard let block = RSAPem.parse(pem) else { return nil }
    switch block.tag {
    case .rsaPublic:
      return publicJWK(fromPkcs1: block.data)
    case .publicKey:
      return pkcs1Data(of: block.data, keyClass: kSecAttrKeyClassPublic).flatMap(publicJWK(fromPkcs1:))
    case .rsaPrivate, .privateKey, nil:
      return pkcs1Data(of: block.data, keyClass: kSecAttrKeyClassPrivate).flatMap(privateJWK(fromPkcs1:))
    }
  }

  private static func pkcs1Data(of keyData: Data, keyClass: CFString) -> Data? {
    RSAKeyLoader.key(from: keyData, keyClass: keyClass).flatMap(RSACrypto.externalRepresentation)
  }

  private static func publicJWK(fromPkcs1 keyData: Data) -> JWK? {
    ASN1DER.integers(inSequence: keyData, count: 2).map { makeJWK(keyOperation: "encrypt", integers: $0) }
  }

  private static func privateJWK(fromPkcs1 keyData: Data) -> JWK? {
    ASN1DER.integers(inSequence: keyData, count: 9).map { makeJWK(keyOperation: "decrypt", integers: Array($0.dropFirst())) }
  }

  private static func makeJWK(keyOperation: String, integers: [Data]) -> JWK {
    let components = integers.map(\.base64URLEncodedString)
    let component = { (index: Int) -> String? in components.indices.contains(index) ? components[index] : nil }
    return JWK(
      kty: keyType,
      alg: algorithm,
      ext: true,
      key_ops: [keyOperation],
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
