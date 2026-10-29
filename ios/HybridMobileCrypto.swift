import Foundation
import MobileCryptoCore
import NitroModules

final class HybridMobileCrypto: HybridMobileCryptoSpec {
  private static let defaultRSAKeySize = 2048.0

  func sha(data: ArrayBuffer, algorithm: SHAAlgorithm) throws -> Promise<ArrayBuffer> {
    let input = data.copiedData()
    return Promise.parallel { ArrayBuffer.copying(algorithm.coreAlgorithm.digest(of: input)) }
  }

  func shaSync(data: ArrayBuffer, algorithm: SHAAlgorithm) throws -> ArrayBuffer {
    ArrayBuffer.copying(algorithm.coreAlgorithm.digest(of: data.copiedData()))
  }

  func hmac256(data: ArrayBuffer, key: ArrayBuffer) throws -> Promise<ArrayBuffer> {
    let content = data.copiedData()
    let keyData = key.copiedData()
    return Promise.parallel { ArrayBuffer.copying(HMACCrypto.hmacSha256(content, key: keyData)) }
  }

  func hmac256Sync(data: ArrayBuffer, key: ArrayBuffer) throws -> ArrayBuffer {
    ArrayBuffer.copying(HMACCrypto.hmacSha256(data.copiedData(), key: key.copiedData()))
  }

  func aesGenerateKey(byteLength: Double) throws -> (any HybridAESKeySpec) {
    let keyData = try AESKeyFactory.generate(byteLength: byteLength.toCount())
      .orThrow("AES key length must be 16, 24 or 32 bytes")
    return HybridAESKey(data: keyData)
  }

  func aesImportKey(base64Url: String) throws -> (any HybridAESKeySpec) {
    let keyData = try AESKeyFactory.importBase64URL(base64Url)
      .orThrow("Expected a base64url AES key of 16, 24 or 32 bytes")
    return HybridAESKey(data: keyData)
  }

  func aesDeriveKey(passwordBase64: String, saltBase64: String, iterations: Double, byteLength: Double, hash: PBKDF2HashAlgorithm) throws -> Promise<(any HybridAESKeySpec)> {
    let iterationCount = try iterations.toCount()
    let keyLength = try byteLength.toCount()
    return Promise.parallel {
      let keyData = try AESKeyFactory.derive(
        passwordBase64: passwordBase64,
        saltBase64: saltBase64,
        iterations: iterationCount,
        byteLength: keyLength,
        hash: hash.coreAlgorithm
      )
      .orThrow("Key derivation failed")
      return HybridAESKey(data: keyData)
    }
  }

  func aesGcmEncrypt(key: (any HybridAESKeySpec), plaintext: String) throws -> Promise<AESGCMCiphertext> {
    let keyData = try key.keyData()
    return Promise.parallel { try Self.aesGcmEncrypt(plaintext, key: keyData) }
  }

  func aesGcmEncryptSync(key: (any HybridAESKeySpec), plaintext: String) throws -> AESGCMCiphertext {
    try Self.aesGcmEncrypt(plaintext, key: key.keyData())
  }

  func aesGcmDecrypt(key: (any HybridAESKeySpec), ciphertext: String, iv: String) throws -> Promise<String> {
    let keyData = try key.keyData()
    return Promise.parallel { try Self.aesGcmDecrypt(ciphertext, iv: iv, key: keyData) }
  }

  func aesGcmDecryptSync(key: (any HybridAESKeySpec), ciphertext: String, iv: String) throws -> String {
    try Self.aesGcmDecrypt(ciphertext, iv: iv, key: key.keyData())
  }

  func aesCbcEncrypt(key: (any HybridAESKeySpec), plaintext: String) throws -> Promise<String> {
    let keyData = try key.keyData()
    return Promise.parallel { try Self.aesCbcEncrypt(plaintext, key: keyData) }
  }

  func aesCbcEncryptSync(key: (any HybridAESKeySpec), plaintext: String) throws -> String {
    try Self.aesCbcEncrypt(plaintext, key: key.keyData())
  }

  func aesCbcDecrypt(key: (any HybridAESKeySpec), ivAndCiphertext: String) throws -> Promise<String> {
    let keyData = try key.keyData()
    return Promise.parallel { try Self.aesCbcDecrypt(ivAndCiphertext, key: keyData) }
  }

  func aesCbcDecryptSync(key: (any HybridAESKeySpec), ivAndCiphertext: String) throws -> String {
    try Self.aesCbcDecrypt(ivAndCiphertext, key: key.keyData())
  }

  func aesEncryptFile(filePath: String) throws -> Promise<EncryptedFile> {
    return Promise.parallel {
      EncryptedFile(try AESCTRFileCrypto.encryptFile(filePath).orThrow("File encryption failed"))
    }
  }

  func aesDecryptFile(filePath: String, key: String, iv: String, sha256: String) throws -> Promise<String> {
    return Promise.parallel {
      try AESCTRFileCrypto.decryptFile(filePath, base64URLKey: key, base64InitializationVector: iv, sha256: sha256)
        .orThrow("File decryption failed")
    }
  }

  func rsaGenerateKeys(keySize: Double?) throws -> Promise<RSAKeyPair> {
    let bitCount = try (keySize ?? Self.defaultRSAKeySize).toCount()
    return Promise.parallel {
      RSAKeyPair(try RSACrypto.generateKeyPair(bitCount: bitCount).orThrow("Key generation failed"))
    }
  }

  func rsaImportPrivateKey(jwk: String) throws -> Promise<(any HybridRSAPrivateKeySpec)> {
    return Promise.parallel {
      HybridRSAPrivateKey(key: try RSAJWKConverter.privateKey(fromJson: jwk).orThrow("Key import failed"))
    }
  }

  func rsaImportPublicKey(jwk: String) throws -> Promise<(any HybridRSAPublicKeySpec)> {
    return Promise.parallel {
      HybridRSAPublicKey(key: try RSAJWKConverter.publicKey(fromJson: jwk).orThrow("Key import failed"))
    }
  }

  func randomUuid() throws -> String {
    RandomGenerator.uuid()
  }

  func randomKey(length: Double) throws -> String {
    try RandomGenerator.bytes(count: length.toCount()).orThrow("Failed to generate random key").lowercaseHexString
  }

  func randomBytes(size: Double) throws -> ArrayBuffer {
    ArrayBuffer.copying(try RandomGenerator.bytes(count: size.toCount()).orThrow("Failed to generate random bytes"))
  }

  private static func aesGcmEncrypt(_ plaintext: String, key: Data) throws -> AESGCMCiphertext {
    let sealed = try AESGCMCrypto.encrypt(plaintext, key: key).orThrow("Encryption failed")
    return AESGCMCiphertext(iv: sealed.iv, ciphertext: sealed.ciphertext)
  }

  private static func aesGcmDecrypt(_ ciphertext: String, iv: String, key: Data) throws -> String {
    try AESGCMCrypto.decrypt(ciphertext, ivBase64: iv, key: key).orThrow("Decryption failed")
  }

  private static func aesCbcEncrypt(_ plaintext: String, key: Data) throws -> String {
    try AESCBCCrypto.encrypt(plaintext, key: key).orThrow("Encryption failed")
  }

  private static func aesCbcDecrypt(_ ivAndCiphertext: String, key: Data) throws -> String {
    try AESCBCCrypto.decrypt(ivAndCiphertext, key: key).orThrow("Decryption failed")
  }
}
