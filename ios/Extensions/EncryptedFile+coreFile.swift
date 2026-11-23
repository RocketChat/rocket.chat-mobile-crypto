import MobileCryptoCore

extension EncryptedFile {
  init(_ coreFile: MobileCryptoCore.EncryptedFile) {
    self.init(path: coreFile.path, key: coreFile.key, iv: coreFile.iv, sha256: coreFile.sha256)
  }

  var coreFile: MobileCryptoCore.EncryptedFile {
    MobileCryptoCore.EncryptedFile(path: path, key: key, iv: iv, sha256: sha256)
  }
}
