import MobileCryptoCore

extension EncryptedFile {
  init(_ coreFile: MobileCryptoCore.EncryptedFile) {
    self.init(path: coreFile.path, key: coreFile.key, iv: coreFile.iv, sha256: coreFile.sha256)
  }
}
