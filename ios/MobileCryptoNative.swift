import Foundation

@objc(MobileCryptoNative)
public final class MobileCryptoNative: NSObject {
  @objc public static func importJwkKey(_ jwkJson: String) -> String? {
    guard let jsonWebKey = try? JSONDecoder().decode(JSONWebKey.self, from: Data(jwkJson.utf8)) else { return nil }
    return RSAJWKConverter.pem(from: jsonWebKey.jwk)
  }

  @objc public static func rsaDecrypt(_ ciphertextBase64: String, privateKeyPem: String) -> String? {
    RSAPemCrypto.decrypt(ciphertextBase64, privateKeyPem: privateKeyPem)
  }

  @objc public static func aesCbcEncryptBase64(_ dataBase64: String, keyHex: String, ivHex: String) -> String? {
    AESCBCCrypto.encryptBase64(dataBase64, keyHex: keyHex, ivHex: ivHex)
  }

  @objc public static func aesCbcDecryptBase64(_ dataBase64: String, keyHex: String, ivHex: String) -> String? {
    AESCBCCrypto.decryptBase64(dataBase64, keyHex: keyHex, ivHex: ivHex)
  }

  @objc public static func aesGcmEncryptBase64(_ dataBase64: String, keyHex: String, ivHex: String) -> String? {
    AESGCMCrypto.encryptBase64(dataBase64, keyHex: keyHex, ivHex: ivHex)
  }

  @objc public static func aesGcmDecryptBase64(_ dataBase64: String, keyHex: String, ivHex: String) -> String? {
    AESGCMCrypto.decryptBase64(dataBase64, keyHex: keyHex, ivHex: ivHex)
  }

  @objc public static func hexString(from data: Data) -> String {
    data.lowercaseHexString
  }

  @objc public static func randomBytes(_ count: Int) -> Data? {
    RandomGenerator.bytes(count: count)
  }
}

private struct JSONWebKey: Decodable {
  let kty: String
  let alg: String?
  let ext: Bool?
  let key_ops: [String]?
  let n: String
  let e: String
  let d: String?
  let p: String?
  let q: String?
  let dp: String?
  let dq: String?
  let qi: String?

  var jwk: JWK {
    JWK(kty: kty, alg: alg, ext: ext, key_ops: key_ops, n: n, e: e, d: d, p: p, q: q, dp: dp, dq: dq, qi: qi)
  }
}
