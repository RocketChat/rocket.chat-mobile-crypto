import Foundation

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
      return RSAPem.format(ASN1DER.sequence(ofIntegers: [modulus, publicExponent]), tag: "RSA PUBLIC")
    }
    let privateComponents = [privateExponentBase64URL, jwk.p, jwk.q, jwk.dp, jwk.dq, jwk.qi]
      .map { $0.flatMap(Data.init(base64URLEncoded:)) }
    guard privateComponents.allSatisfy({ $0 != nil }) else { return nil }
    let integers = [privateKeyVersion, modulus, publicExponent] + privateComponents.compactMap { $0 }
    return RSAPem.format(ASN1DER.sequence(ofIntegers: integers), tag: "RSA PRIVATE")
  }

  static func jwk(fromPem pem: String) -> JWK? {
    guard let keyData = RSAPem.parse(pem) else { return nil }
    if pem.contains("PUBLIC") {
      let isPkcs1 = pem.contains("RSA")
      guard let publicKeyData = isPkcs1 ? keyData : RSAKeyLoader.publicKey(fromPem: pem).flatMap(RSACrypto.externalRepresentation),
            let integers = ASN1DER.integers(inSequence: publicKeyData, count: 2) else {
        return nil
      }
      return makeJWK(keyOperation: "encrypt", integers: integers)
    }
    guard let privateKey = RSAKeyLoader.privateKey(fromPem: pem),
          let privateKeyData = RSACrypto.externalRepresentation(of: privateKey),
          let integers = ASN1DER.integers(inSequence: privateKeyData, count: 9) else {
      return nil
    }
    return makeJWK(keyOperation: "decrypt", integers: Array(integers.dropFirst()))
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
