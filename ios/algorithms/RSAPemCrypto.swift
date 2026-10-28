import Foundation

enum RSAPemCrypto {
  private static let defaultSignatureHash = RSAHashAlgorithm.sha512

  static func encrypt(_ message: String, publicKeyPem: String) -> String? {
    encryptedBase64(Data(message.utf8), publicKeyPem: publicKeyPem)
  }

  static func encryptBase64(_ messageBase64: String, publicKeyPem: String) -> String? {
    Data(base64Encoded: messageBase64).flatMap { encryptedBase64($0, publicKeyPem: publicKeyPem) }
  }

  static func decrypt(_ ciphertextBase64: String, privateKeyPem: String) -> String? {
    decryptedData(ciphertextBase64, privateKeyPem: privateKeyPem).flatMap { String(data: $0, encoding: .utf8) }
  }

  static func decryptToBase64(_ ciphertextBase64: String, privateKeyPem: String) -> String? {
    decryptedData(ciphertextBase64, privateKeyPem: privateKeyPem)?.base64EncodedString()
  }

  static func sign(_ message: String, privateKeyPem: String, hash: RSAHashAlgorithm?) -> String? {
    signatureBase64(Data(message.utf8), privateKeyPem: privateKeyPem, hash: hash)
  }

  static func signBase64(_ messageBase64: String, privateKeyPem: String, hash: RSAHashAlgorithm?) -> String? {
    Data(base64Encoded: messageBase64).flatMap { signatureBase64($0, privateKeyPem: privateKeyPem, hash: hash) }
  }

  static func verify(_ signatureBase64: String, message: String, publicKeyPem: String, hash: RSAHashAlgorithm?) -> Bool {
    isValidSignature(signatureBase64, message: Data(message.utf8), publicKeyPem: publicKeyPem, hash: hash)
  }

  static func verifyBase64(_ signatureBase64: String, messageBase64: String, publicKeyPem: String, hash: RSAHashAlgorithm?) -> Bool {
    guard let message = Data(base64Encoded: messageBase64) else { return false }
    return isValidSignature(signatureBase64, message: message, publicKeyPem: publicKeyPem, hash: hash)
  }

  private static func encryptedBase64(_ plaintext: Data, publicKeyPem: String) -> String? {
    guard let publicKey = RSAKeyLoader.publicKey(fromPem: publicKeyPem) else { return nil }
    return RSACrypto.encrypt(plaintext, using: publicKey)?.base64EncodedString()
  }

  private static func decryptedData(_ ciphertextBase64: String, privateKeyPem: String) -> Data? {
    guard let privateKey = RSAKeyLoader.privateKey(fromPem: privateKeyPem),
          let ciphertext = Data(base64Encoded: ciphertextBase64) else {
      return nil
    }
    return RSACrypto.decrypt(ciphertext, using: privateKey)
  }

  private static func signatureBase64(_ message: Data, privateKeyPem: String, hash: RSAHashAlgorithm?) -> String? {
    guard let privateKey = RSAKeyLoader.privateKey(fromPem: privateKeyPem) else { return nil }
    return RSACrypto.sign(message, using: privateKey, hash: hash ?? defaultSignatureHash)?.base64EncodedString()
  }

  private static func isValidSignature(_ signatureBase64: String, message: Data, publicKeyPem: String, hash: RSAHashAlgorithm?) -> Bool {
    guard let publicKey = RSAKeyLoader.publicKey(fromPem: publicKeyPem),
          let signature = Data(base64Encoded: signatureBase64) else {
      return false
    }
    return RSACrypto.verify(signature, message: message, using: publicKey, hash: hash ?? defaultSignatureHash)
  }
}
