import Foundation
import MobileCryptoCore
import NitroModules

final class HybridMobileCrypto: HybridMobileCryptoSpec {
  private static let defaultRSAKeySize = 2048.0

  func sha(data: ArrayBuffer, algorithm: SHAAlgorithm) throws -> Promise<ArrayBuffer> {
    let input = ArrayBuffer.copy(of: data)
    return Promise.parallel { try self.shaSync(data: input, algorithm: algorithm) }
  }

  func shaSync(data: ArrayBuffer, algorithm: SHAAlgorithm) throws -> ArrayBuffer {
    ArrayBuffer.copying(algorithm.coreAlgorithm.digest(of: data.toData(copyIfNeeded: true)))
  }

  func hmac256(data: ArrayBuffer, key: ArrayBuffer) throws -> Promise<ArrayBuffer> {
    let (input, keyCopy) = (ArrayBuffer.copy(of: data), ArrayBuffer.copy(of: key))
    return Promise.parallel { try self.hmac256Sync(data: input, key: keyCopy) }
  }

  func hmac256Sync(data: ArrayBuffer, key: ArrayBuffer) throws -> ArrayBuffer {
    ArrayBuffer.copying(HMACCrypto.hmacSha256(data.toData(copyIfNeeded: true), key: key.toData(copyIfNeeded: true)))
  }

  func aesGenerateKey(byteLength: Double) throws -> (any HybridAESKeySpec) {
    let key = try AESKey.generate(byteLength: byteLength.toCount())
      .orThrow("AES key length must be 16 or 32 bytes")
    return HybridAESKey(key: key)
  }

  func aesImportKey(base64Url: String) throws -> (any HybridAESKeySpec) {
    let key = try AESKey(base64URL: base64Url)
      .orThrow("Expected a base64url AES key of 16 or 32 bytes")
    return HybridAESKey(key: key)
  }

  func aesDeriveKey(passwordBase64: String, saltBase64: String, iterations: Double, byteLength: Double, hash: PBKDF2HashAlgorithm) throws -> Promise<(any HybridAESKeySpec)> {
    let iterationCount = try iterations.toCount()
    let keyLength = try byteLength.toCount()
    return Promise.parallel {
      let key = try AESKey.derive(
        passwordBase64: passwordBase64,
        saltBase64: saltBase64,
        iterations: iterationCount,
        byteLength: keyLength,
        hash: hash.coreAlgorithm
      )
      .orThrow("Key derivation failed")
      return HybridAESKey(key: key)
    }
  }

  func aesGcmEncrypt(key: (any HybridAESKeySpec), plaintext: String) throws -> Promise<AESGCMCiphertext> {
    Promise.parallel { try self.aesGcmEncryptSync(key: key, plaintext: plaintext) }
  }

  func aesGcmEncryptSync(key: (any HybridAESKeySpec), plaintext: String) throws -> AESGCMCiphertext {
    let sealed = try AESGCMCrypto.encrypt(plaintext, key: key.aesKey()).orThrow("Encryption failed")
    return AESGCMCiphertext(iv: sealed.iv, ciphertext: sealed.ciphertext)
  }

  func aesGcmDecrypt(key: (any HybridAESKeySpec), encrypted: AESGCMCiphertext) throws -> Promise<String> {
    Promise.parallel { try self.aesGcmDecryptSync(key: key, encrypted: encrypted) }
  }

  func aesGcmDecryptSync(key: (any HybridAESKeySpec), encrypted: AESGCMCiphertext) throws -> String {
    try AESGCMCrypto.decrypt(encrypted.ciphertext, ivBase64: encrypted.iv, key: key.aesKey()).orThrow("Decryption failed")
  }

  func aesCbcEncrypt(key: (any HybridAESKeySpec), plaintext: String) throws -> Promise<String> {
    Promise.parallel { try self.aesCbcEncryptSync(key: key, plaintext: plaintext) }
  }

  func aesCbcEncryptSync(key: (any HybridAESKeySpec), plaintext: String) throws -> String {
    try AESCBCCrypto.encrypt(plaintext, key: key.aesKey()).orThrow("Encryption failed")
  }

  func aesCbcDecrypt(key: (any HybridAESKeySpec), ivAndCiphertext: String) throws -> Promise<String> {
    Promise.parallel { try self.aesCbcDecryptSync(key: key, ivAndCiphertext: ivAndCiphertext) }
  }

  func aesCbcDecryptSync(key: (any HybridAESKeySpec), ivAndCiphertext: String) throws -> String {
    try AESCBCCrypto.decrypt(ivAndCiphertext, key: key.aesKey()).orThrow("Decryption failed")
  }

  func aesEncryptFile(filePath: String) throws -> Promise<EncryptedFile> {
    return Promise.parallel {
      EncryptedFile(try AESCTRFileCrypto.encryptFile(filePath).orThrow("File encryption failed"))
    }
  }

  func aesDecryptFile(file: EncryptedFile) throws -> Promise<String> {
    return Promise.parallel {
      try AESCTRFileCrypto.decryptFile(file.coreFile).orThrow("File decryption failed")
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

  func rsaEncrypt(publicKey: (any HybridRSAPublicKeySpec), plaintext: String) throws -> String {
    try RSACrypto.encrypt(plaintext, using: publicKey.secKey()).orThrow("Encryption failed")
  }

  func rsaDecrypt(privateKey: (any HybridRSAPrivateKeySpec), ciphertext: String) throws -> Promise<String> {
    let key = try privateKey.secKey()
    return Promise.parallel {
      try RSACrypto.decrypt(ciphertext, using: key).orThrow("Decryption failed")
    }
  }

  func rsaSign(privateKey: (any HybridRSAPrivateKeySpec), message: ArrayBuffer, hash: RSAHashAlgorithm) throws -> Promise<ArrayBuffer> {
    let key = try privateKey.secKey()
    let messageData = message.toData(copyIfNeeded: true)
    return Promise.parallel {
      ArrayBuffer.copying(try RSACrypto.sign(messageData, using: key, hash: hash.coreAlgorithm).orThrow("Signing failed"))
    }
  }

  func rsaVerify(publicKey: (any HybridRSAPublicKeySpec), signature: ArrayBuffer, message: ArrayBuffer, hash: RSAHashAlgorithm) throws -> Bool {
    RSACrypto.verify(signature.toData(copyIfNeeded: true), message: message.toData(copyIfNeeded: true), using: try publicKey.secKey(), hash: hash.coreAlgorithm)
  }

  func rsaVerifyJwt(publicKey: (any HybridRSAPublicKeySpec), jwt: String) throws -> Promise<String> {
    let key = try publicKey.secKey()
    return Promise.parallel {
      try RSACrypto.verifiedJwtPayload(jwt, using: key).orThrow("JWT verification failed")
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
}
