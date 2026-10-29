import Foundation
import Security

public enum MobileCryptoNative {
  public static func rsaImportPrivateKey(_ jwk: String) -> SecKey? {
    RSAJWKConverter.privateKey(fromJson: jwk)
  }

  public static func rsaDecrypt(_ ciphertext: String, privateKey: SecKey) -> String? {
    RSACrypto.decrypt(ciphertext, using: privateKey)
  }

  public static func aesImportKey(_ base64Url: String) -> Data? {
    AESKeyFactory.importBase64URL(base64Url)
  }

  public static func aesGcmDecrypt(_ ciphertext: String, iv: String, key: Data) -> String? {
    AESGCMCrypto.decrypt(ciphertext, ivBase64: iv, key: key)
  }

  public static func aesGcmEncrypt(_ plaintext: String, key: Data) -> (iv: String, ciphertext: String)? {
    AESGCMCrypto.encrypt(plaintext, key: key)
  }

  public static func aesCbcDecrypt(_ ivAndCiphertext: String, key: Data) -> String? {
    AESCBCCrypto.decrypt(ivAndCiphertext, key: key)
  }

  public static func aesCbcEncrypt(_ plaintext: String, key: Data) -> String? {
    AESCBCCrypto.encrypt(plaintext, key: key)
  }
}
