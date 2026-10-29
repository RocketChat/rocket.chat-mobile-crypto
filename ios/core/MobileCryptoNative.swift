import Foundation

public enum MobileCryptoNative {
  public static func importJwkKey(_ jwkJson: String) -> String? {
    guard let jwk = try? JSONDecoder().decode(JWK.self, from: Data(jwkJson.utf8)) else { return nil }
    return RSAJWKConverter.pem(from: jwk)
  }

  public static func rsaDecrypt(_ ciphertextBase64: String, privateKeyPem: String) -> String? {
    RSAPemCrypto.decrypt(ciphertextBase64, privateKeyPem: privateKeyPem)
  }

  public static func aesCbcEncryptBase64(_ dataBase64: String, keyHex: String, ivHex: String) -> String? {
    AESCBCCrypto.encryptBase64(dataBase64, keyHex: keyHex, ivHex: ivHex)
  }

  public static func aesCbcDecryptBase64(_ dataBase64: String, keyHex: String, ivHex: String) -> String? {
    AESCBCCrypto.decryptBase64(dataBase64, keyHex: keyHex, ivHex: ivHex)
  }

  public static func aesGcmEncryptBase64(_ dataBase64: String, keyHex: String, ivHex: String) -> String? {
    AESGCMCrypto.encryptBase64(dataBase64, keyHex: keyHex, ivHex: ivHex)
  }

  public static func aesGcmDecryptBase64(_ dataBase64: String, keyHex: String, ivHex: String) -> String? {
    AESGCMCrypto.decryptBase64(dataBase64, keyHex: keyHex, ivHex: ivHex)
  }

  public static func hexString(from data: Data) -> String {
    data.lowercaseHexString
  }

  public static func randomBytes(_ count: Int) -> Data? {
    RandomGenerator.bytes(count: count)
  }
}
