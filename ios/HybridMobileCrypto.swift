import Foundation
import NitroModules

final class HybridMobileCrypto: HybridMobileCryptoSpec {
  private static let defaultRSAKeySize = 2048.0

  func shaBase64(data: String, algorithm: String) throws -> Promise<String> {
    return Promise.parallel { try self.shaBase64Sync(data: data, algorithm: algorithm) }
  }

  func shaBase64Sync(data: String, algorithm: String) throws -> String {
    try SHACrypto.hashBase64(data, algorithm: algorithm).orThrow("Invalid algorithm or input")
  }

  func shaUtf8(data: String, algorithm: String) throws -> Promise<String> {
    return Promise.parallel { try self.shaUtf8Sync(data: data, algorithm: algorithm) }
  }

  func shaUtf8Sync(data: String, algorithm: String) throws -> String {
    try SHACrypto.hashUtf8ToHex(data, algorithm: algorithm).orThrow("Invalid algorithm")
  }

  func pbkdf2Hash(pwdBase64: String, saltBase64: String, iterations: Double, keyLen: Double, hash: String) throws -> Promise<String> {
    return Promise.parallel {
      let iterationCount = try iterations.toCount()
      let keyLength = try keyLen.toCount()
      return try ObjCExceptionCatcher.catching {
        PBKDF2Crypto.deriveKeyBase64(
          pwdBase64,
          saltBase64: saltBase64,
          iterations: iterationCount,
          keyLength: keyLength,
          hashAlgorithm: hash
        )
      }
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
    AESGCMCrypto.encryptGcmBase64(dataBase64, keyHex: keyHex, ivHex: ivHex)
  }

  func aesGcmDecrypt(dataBase64: String, keyHex: String, ivHex: String) throws -> Promise<String?> {
    return Promise.parallel { try self.aesGcmDecryptSync(dataBase64: dataBase64, keyHex: keyHex, ivHex: ivHex) }
  }

  func aesGcmDecryptSync(dataBase64: String, keyHex: String, ivHex: String) throws -> String? {
    AESGCMCrypto.decryptGcmBase64(dataBase64, keyHex: keyHex, ivHex: ivHex)
  }

  func aesEncryptFile(filePath: String, base64UrlKey: String, base64Iv: String) throws -> Promise<String> {
    return Promise.parallel {
      try ObjCExceptionCatcher.catching {
        AESCrypto.encryptFile(filePath, base64UrlKey: base64UrlKey, base64Iv: base64Iv)
      }
      .orThrow("File encryption failed")
    }
  }

  func aesDecryptFile(filePath: String, base64UrlKey: String, base64Iv: String) throws -> Promise<String> {
    return Promise.parallel {
      try ObjCExceptionCatcher.catching {
        AESCrypto.decryptFile(filePath, base64UrlKey: base64UrlKey, base64Iv: base64Iv)
      }
      .orThrow("File decryption failed")
    }
  }

  func randomUuid() throws -> String {
    try ObjCExceptionCatcher.catching { RandomUtils.generateUuid() }
  }

  func randomKey(length: Double) throws -> String {
    let byteCount = try length.toCount()
    return try ObjCExceptionCatcher.catching { RandomUtils.generateRandomKeyHex(byteCount) }
      .orThrow("Failed to generate random key")
  }

  func randomBytes(size: Double) throws -> String {
    let byteCount = try size.toCount()
    return try ObjCExceptionCatcher.catching { RandomUtils.generateRandomBytesBase64(byteCount) }
      .orThrow("Failed to generate random bytes")
  }

  func rsaGenerateKeys(keySize: Double?) throws -> Promise<RSAKeyPair> {
    return Promise.parallel {
      let bitCount = try (keySize ?? Self.defaultRSAKeySize).toCount()
      let keyPair = try ObjCExceptionCatcher.catching { RSACrypto.generateKeyPair(Int(bitCount)) }
        .orThrow("Key generation failed")
      return try RSAKeyPair.from(dictionary: keyPair)
    }
  }

  func rsaEncrypt(message: String, publicKey: String) throws -> String {
    try ObjCExceptionCatcher.catching { RSACrypto.encrypt(message, publicKeyPem: publicKey) }
      .orThrow("Encryption failed")
  }

  func rsaEncrypt64(message: String, publicKey: String) throws -> String {
    try ObjCExceptionCatcher.catching { RSACrypto.encryptBase64(message, publicKeyPem: publicKey) }
      .orThrow("Encryption failed")
  }

  func rsaDecrypt(encodedMessage: String, privateKey: String) throws -> Promise<String> {
    return Promise.parallel {
      try ObjCExceptionCatcher.catching { RSACrypto.decrypt(encodedMessage, privateKeyPem: privateKey) }
        .orThrow("Decryption failed")
    }
  }

  func rsaDecrypt64(encodedMessage: String, privateKey: String) throws -> Promise<String> {
    return Promise.parallel {
      try ObjCExceptionCatcher.catching { RSACrypto.decrypt(toBase64: encodedMessage, privateKeyPem: privateKey) }
        .orThrow("Decryption failed")
    }
  }

  func rsaSign(message: String, privateKey: String, hash: String?) throws -> Promise<String> {
    return Promise.parallel {
      try ObjCExceptionCatcher.catching {
        RSACrypto.sign(message, privateKeyPem: privateKey, hashAlgorithm: hash)
      }
      .orThrow("Signing failed")
    }
  }

  func rsaSign64(message: String, privateKey: String, hash: String?) throws -> Promise<String> {
    return Promise.parallel {
      try ObjCExceptionCatcher.catching {
        RSACrypto.signBase64(message, privateKeyPem: privateKey, hashAlgorithm: hash)
      }
      .orThrow("Signing failed")
    }
  }

  func rsaVerify(signature: String, message: String, publicKey: String, hash: String?) throws -> Promise<Bool> {
    return Promise.parallel {
      try self.rsaVerifySync(signature: signature, message: message, publicKey: publicKey, hash: hash)
    }
  }

  func rsaVerifySync(signature: String, message: String, publicKey: String, hash: String?) throws -> Bool {
    try ObjCExceptionCatcher.catching {
      RSACrypto.verify(signature, message: message, publicKeyPem: publicKey, hashAlgorithm: hash)
    }
  }

  func rsaVerify64(signature: String, message: String, publicKey: String, hash: String?) throws -> Promise<Bool> {
    return Promise.parallel {
      try self.rsaVerify64Sync(signature: signature, message: message, publicKey: publicKey, hash: hash)
    }
  }

  func rsaVerify64Sync(signature: String, message: String, publicKey: String, hash: String?) throws -> Bool {
    try ObjCExceptionCatcher.catching {
      RSACrypto.verifyBase64(signature, messageBase64: message, publicKeyPem: publicKey, hashAlgorithm: hash)
    }
  }

  func calculateFileChecksum(filePath: String) throws -> Promise<String> {
    return Promise.parallel {
      try ObjCExceptionCatcher.catching { FileUtils.calculateSha256Checksum(filePath) }
        .orThrow("File checksum calculation failed")
    }
  }

  func getRandomValues(length: Double) throws -> String {
    let characterCount = try length.toCount()
    return try ObjCExceptionCatcher.catching { RandomUtils.generateRandomAlphanumeric(characterCount) }
  }

  func rsaImportKey(jwk: JWK) throws -> Promise<String> {
    return Promise.parallel {
      let jwkDictionary = jwk.toDictionary()
      return try ObjCExceptionCatcher.catching { RSACrypto.importJwkKey(jwkDictionary) }
        .orThrow("Key import failed")
    }
  }

  func rsaExportKey(pem: String) throws -> Promise<JWK> {
    return Promise.parallel {
      let jwkDictionary = try ObjCExceptionCatcher.catching { RSACrypto.exportPemKey(pem) }
        .orThrow("Key export failed")
      return try JWK.from(dictionary: jwkDictionary)
    }
  }
}
