import Foundation
import MobileCryptoCore
import NitroModules

final class HybridMobileCrypto: HybridMobileCryptoSpec {
  private static let defaultRSAKeySize = 2048.0

  func shaBase64(data: String, algorithm: SHAAlgorithm) throws -> Promise<String> {
    return Promise.parallel { try self.shaBase64Sync(data: data, algorithm: algorithm) }
  }

  func shaBase64Sync(data: String, algorithm: SHAAlgorithm) throws -> String {
    try SHACrypto.hashBase64(data, algorithm: algorithm.coreAlgorithm).orThrow("Invalid algorithm or input")
  }

  func shaUtf8(data: String, algorithm: SHAAlgorithm) throws -> Promise<String> {
    return Promise.parallel { try self.shaUtf8Sync(data: data, algorithm: algorithm) }
  }

  func shaUtf8Sync(data: String, algorithm: SHAAlgorithm) throws -> String {
    SHACrypto.hashUtf8ToHex(data, algorithm: algorithm.coreAlgorithm)
  }

  func pbkdf2Hash(pwdBase64: String, saltBase64: String, iterations: Double, keyLen: Double, hash: PBKDF2HashAlgorithm) throws -> Promise<String> {
    return Promise.parallel {
      try PBKDF2Crypto.deriveKeyBase64(
        pwdBase64,
        saltBase64: saltBase64,
        iterations: iterations.toCount(),
        keyLength: keyLen.toCount(),
        hash: hash.coreAlgorithm
      )
      .orThrow("PBKDF2 derivation failed")
    }
  }

  func hmac256(data: String, key: String) throws -> Promise<String> {
    return Promise.parallel { try self.hmac256Sync(data: data, key: key) }
  }

  func hmac256Sync(data: String, key: String) throws -> String {
    try HMACCrypto.hmacSha256Hex(data, keyHex: key).orThrow("HMAC computation failed")
  }

  func aesEncrypt(dataBase64: String, keyHex: String, ivHex: String) throws -> Promise<String?> {
    return Promise.parallel { try self.aesEncryptSync(dataBase64: dataBase64, keyHex: keyHex, ivHex: ivHex) }
  }

  func aesEncryptSync(dataBase64: String, keyHex: String, ivHex: String) throws -> String? {
    if dataBase64.isEmpty {
      return nil
    }
    return try AESCBCCrypto.encryptBase64(dataBase64, keyHex: keyHex, ivHex: ivHex).orThrow("Encryption failed")
  }

  func aesDecrypt(dataBase64: String, keyHex: String, ivHex: String) throws -> Promise<String?> {
    return Promise.parallel { try self.aesDecryptSync(dataBase64: dataBase64, keyHex: keyHex, ivHex: ivHex) }
  }

  func aesDecryptSync(dataBase64: String, keyHex: String, ivHex: String) throws -> String? {
    if dataBase64.isEmpty {
      return nil
    }
    return try AESCBCCrypto.decryptBase64(dataBase64, keyHex: keyHex, ivHex: ivHex).orThrow("Decryption failed")
  }

  func aesGcmEncrypt(dataBase64: String, keyHex: String, ivHex: String) throws -> Promise<String?> {
    return Promise.parallel { try self.aesGcmEncryptSync(dataBase64: dataBase64, keyHex: keyHex, ivHex: ivHex) }
  }

  func aesGcmEncryptSync(dataBase64: String, keyHex: String, ivHex: String) throws -> String? {
    AESGCMCrypto.encryptBase64(dataBase64, keyHex: keyHex, ivHex: ivHex)
  }

  func aesGcmDecrypt(dataBase64: String, keyHex: String, ivHex: String) throws -> Promise<String?> {
    return Promise.parallel { try self.aesGcmDecryptSync(dataBase64: dataBase64, keyHex: keyHex, ivHex: ivHex) }
  }

  func aesGcmDecryptSync(dataBase64: String, keyHex: String, ivHex: String) throws -> String? {
    AESGCMCrypto.decryptBase64(dataBase64, keyHex: keyHex, ivHex: ivHex)
  }

  func aesEncryptFile(filePath: String, base64UrlKey: String, base64Iv: String) throws -> Promise<String> {
    return Promise.parallel {
      try AESCTRFileCrypto.encryptFile(filePath, base64URLKey: base64UrlKey, base64InitializationVector: base64Iv)
        .orThrow("File encryption failed")
    }
  }

  func aesDecryptFile(filePath: String, base64UrlKey: String, base64Iv: String) throws -> Promise<String> {
    return Promise.parallel {
      try AESCTRFileCrypto.decryptFile(filePath, base64URLKey: base64UrlKey, base64InitializationVector: base64Iv)
        .orThrow("File decryption failed")
    }
  }

  func randomUuid() throws -> String {
    RandomGenerator.uuid()
  }

  func randomKey(length: Double) throws -> String {
    try RandomGenerator.bytes(count: length.toCount()).orThrow("Failed to generate random key").lowercaseHexString
  }

  func randomBytes(size: Double) throws -> String {
    try RandomGenerator.bytes(count: size.toCount()).orThrow("Failed to generate random bytes").base64EncodedString()
  }

  func rsaGenerateKeys(keySize: Double?) throws -> Promise<RSAKeyPair> {
    return Promise.parallel {
      let bitCount = try (keySize ?? Self.defaultRSAKeySize).toCount()
      return RSAKeyPair(try RSACrypto.generateKeyPair(bitCount: bitCount).orThrow("Key generation failed"))
    }
  }

  func rsaEncrypt(message: String, publicKey: String) throws -> String {
    try RSAPemCrypto.encrypt(message, publicKeyPem: publicKey).orThrow("Encryption failed")
  }

  func rsaEncrypt64(message: String, publicKey: String) throws -> String {
    try RSAPemCrypto.encryptBase64(message, publicKeyPem: publicKey).orThrow("Encryption failed")
  }

  func rsaDecrypt(encodedMessage: String, privateKey: String) throws -> Promise<String> {
    return Promise.parallel {
      try RSAPemCrypto.decrypt(encodedMessage, privateKeyPem: privateKey).orThrow("Decryption failed")
    }
  }

  func rsaDecrypt64(encodedMessage: String, privateKey: String) throws -> Promise<String> {
    return Promise.parallel {
      try RSAPemCrypto.decryptToBase64(encodedMessage, privateKeyPem: privateKey).orThrow("Decryption failed")
    }
  }

  func rsaSign(message: String, privateKey: String, hash: RSAHashAlgorithm?) throws -> Promise<String> {
    return Promise.parallel {
      try RSAPemCrypto.sign(message, privateKeyPem: privateKey, hash: hash?.coreAlgorithm).orThrow("Signing failed")
    }
  }

  func rsaSign64(message: String, privateKey: String, hash: RSAHashAlgorithm?) throws -> Promise<String> {
    return Promise.parallel {
      try RSAPemCrypto.signBase64(message, privateKeyPem: privateKey, hash: hash?.coreAlgorithm).orThrow("Signing failed")
    }
  }

  func rsaVerify(signature: String, message: String, publicKey: String, hash: RSAHashAlgorithm?) throws -> Promise<Bool> {
    return Promise.parallel {
      try self.rsaVerifySync(signature: signature, message: message, publicKey: publicKey, hash: hash)
    }
  }

  func rsaVerifySync(signature: String, message: String, publicKey: String, hash: RSAHashAlgorithm?) throws -> Bool {
    RSAPemCrypto.verify(signature, message: message, publicKeyPem: publicKey, hash: hash?.coreAlgorithm)
  }

  func rsaVerify64(signature: String, message: String, publicKey: String, hash: RSAHashAlgorithm?) throws -> Promise<Bool> {
    return Promise.parallel {
      try self.rsaVerify64Sync(signature: signature, message: message, publicKey: publicKey, hash: hash)
    }
  }

  func rsaVerify64Sync(signature: String, message: String, publicKey: String, hash: RSAHashAlgorithm?) throws -> Bool {
    RSAPemCrypto.verifyBase64(signature, messageBase64: message, publicKeyPem: publicKey, hash: hash?.coreAlgorithm)
  }

  func calculateFileChecksum(filePath: String) throws -> Promise<String> {
    return Promise.parallel {
      try FileChecksum.sha256Hex(ofFileAt: filePath).orThrow("File checksum calculation failed")
    }
  }

  func getRandomValues(length: Double) throws -> String {
    try RandomGenerator.alphanumeric(length: length.toCount()).orThrow("Failed to generate random values")
  }

  func rsaImportKey(jwk: JWK) throws -> Promise<String> {
    return Promise.parallel {
      try RSAJWKConverter.pem(from: jwk.coreKey).orThrow("Key import failed")
    }
  }

  func rsaExportKey(pem: String) throws -> Promise<JWK> {
    return Promise.parallel {
      JWK(try RSAJWKConverter.jwk(fromPem: pem).orThrow("Key export failed"))
    }
  }

  func rsaImportPrivateKey(pem: String) throws -> Promise<(any HybridRSAPrivateKeySpec)> {
    return Promise.parallel {
      HybridRSAPrivateKey(key: try RSAKeyLoader.privateKey(fromPem: pem).orThrow("Key import failed"))
    }
  }

  func rsaImportPublicKey(pem: String) throws -> Promise<(any HybridRSAPublicKeySpec)> {
    return Promise.parallel {
      HybridRSAPublicKey(key: try RSAKeyLoader.publicKey(fromPem: pem).orThrow("Key import failed"))
    }
  }

  func shaBuffer(data: ArrayBuffer, algorithm: SHAAlgorithm) throws -> Promise<ArrayBuffer> {
    let input = ArrayBuffer.copy(of: data)
    return Promise.parallel { try self.shaBufferSync(data: input, algorithm: algorithm) }
  }

  func shaBufferSync(data: ArrayBuffer, algorithm: SHAAlgorithm) throws -> ArrayBuffer {
    ArrayBuffer.copying(algorithm.coreAlgorithm.digest(of: data.toData(copyIfNeeded: true)))
  }

  func hmac256Buffer(data: ArrayBuffer, key: ArrayBuffer) throws -> Promise<ArrayBuffer> {
    let (input, keyCopy) = (ArrayBuffer.copy(of: data), ArrayBuffer.copy(of: key))
    return Promise.parallel { try self.hmac256BufferSync(data: input, key: keyCopy) }
  }

  func hmac256BufferSync(data: ArrayBuffer, key: ArrayBuffer) throws -> ArrayBuffer {
    ArrayBuffer.copying(HMACCrypto.hmacSha256(data.toData(copyIfNeeded: true), key: key.toData(copyIfNeeded: true)))
  }

  func aesEncryptBuffer(data: ArrayBuffer, key: ArrayBuffer, iv: ArrayBuffer) throws -> Promise<ArrayBuffer> {
    let (input, keyCopy, ivCopy) = (ArrayBuffer.copy(of: data), ArrayBuffer.copy(of: key), ArrayBuffer.copy(of: iv))
    return Promise.parallel { try self.aesEncryptBufferSync(data: input, key: keyCopy, iv: ivCopy) }
  }

  func aesEncryptBufferSync(data: ArrayBuffer, key: ArrayBuffer, iv: ArrayBuffer) throws -> ArrayBuffer {
    ArrayBuffer.copying(
      try AESCBCCrypto.encrypt(data.toData(copyIfNeeded: true), key: key.toData(copyIfNeeded: true), initializationVector: iv.toData(copyIfNeeded: true))
        .orThrow("Encryption failed")
    )
  }

  func aesDecryptBuffer(data: ArrayBuffer, key: ArrayBuffer, iv: ArrayBuffer) throws -> Promise<ArrayBuffer> {
    let (input, keyCopy, ivCopy) = (ArrayBuffer.copy(of: data), ArrayBuffer.copy(of: key), ArrayBuffer.copy(of: iv))
    return Promise.parallel { try self.aesDecryptBufferSync(data: input, key: keyCopy, iv: ivCopy) }
  }

  func aesDecryptBufferSync(data: ArrayBuffer, key: ArrayBuffer, iv: ArrayBuffer) throws -> ArrayBuffer {
    ArrayBuffer.copying(
      try AESCBCCrypto.decrypt(data.toData(copyIfNeeded: true), key: key.toData(copyIfNeeded: true), initializationVector: iv.toData(copyIfNeeded: true))
        .orThrow("Decryption failed")
    )
  }

  func aesGcmEncryptBuffer(data: ArrayBuffer, key: ArrayBuffer, iv: ArrayBuffer) throws -> Promise<ArrayBuffer> {
    let (input, keyCopy, ivCopy) = (ArrayBuffer.copy(of: data), ArrayBuffer.copy(of: key), ArrayBuffer.copy(of: iv))
    return Promise.parallel { try self.aesGcmEncryptBufferSync(data: input, key: keyCopy, iv: ivCopy) }
  }

  func aesGcmEncryptBufferSync(data: ArrayBuffer, key: ArrayBuffer, iv: ArrayBuffer) throws -> ArrayBuffer {
    ArrayBuffer.copying(
      try AESGCMCrypto.encrypt(data.toData(copyIfNeeded: true), key: key.toData(copyIfNeeded: true), nonce: iv.toData(copyIfNeeded: true)).orThrow("Encryption failed")
    )
  }

  func aesGcmDecryptBuffer(data: ArrayBuffer, key: ArrayBuffer, iv: ArrayBuffer) throws -> Promise<ArrayBuffer> {
    let (input, keyCopy, ivCopy) = (ArrayBuffer.copy(of: data), ArrayBuffer.copy(of: key), ArrayBuffer.copy(of: iv))
    return Promise.parallel { try self.aesGcmDecryptBufferSync(data: input, key: keyCopy, iv: ivCopy) }
  }

  func aesGcmDecryptBufferSync(data: ArrayBuffer, key: ArrayBuffer, iv: ArrayBuffer) throws -> ArrayBuffer {
    ArrayBuffer.copying(
      try AESGCMCrypto.decrypt(data.toData(copyIfNeeded: true), key: key.toData(copyIfNeeded: true), nonce: iv.toData(copyIfNeeded: true)).orThrow("Decryption failed")
    )
  }

  func randomBytesBuffer(size: Double) throws -> ArrayBuffer {
    ArrayBuffer.copying(try RandomGenerator.bytes(count: size.toCount()).orThrow("Failed to generate random bytes"))
  }
}
