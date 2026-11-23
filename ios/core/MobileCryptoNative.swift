import Foundation
import Security

public enum MobileCryptoNative {
  public static func rsaImportPrivateKey(_ jwk: String) -> SecKey? {
    RSAJWKConverter.privateKey(fromJson: jwk)
  }

  public static func rsaDecrypt(_ ciphertext: String, privateKey: SecKey) -> String? {
    RSACrypto.decrypt(ciphertext, using: privateKey)
  }

  public static func aesImportKey(_ base64Url: String) -> AESKey? {
    AESKey(base64URL: base64Url)
  }

  public static func aesGcmDecrypt(_ ciphertext: String, iv: String, key: AESKey) -> String? {
    AESGCMCrypto.decrypt(ciphertext, ivBase64: iv, key: key)
  }

  public static func aesGcmEncrypt(_ plaintext: String, key: AESKey) -> (iv: String, ciphertext: String)? {
    AESGCMCrypto.encrypt(plaintext, key: key)
  }

  public static func aesCbcDecrypt(_ ivAndCiphertext: String, key: AESKey) -> String? {
    AESCBCCrypto.decrypt(ivAndCiphertext, key: key)
  }

  public static func aesCbcEncrypt(_ plaintext: String, key: AESKey) -> String? {
    AESCBCCrypto.encrypt(plaintext, key: key)
  }
}
