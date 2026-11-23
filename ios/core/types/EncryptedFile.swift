package struct EncryptedFile {
  package let path: String
  package let key: String
  package let iv: String
  package let sha256: String

  package init(path: String, key: String, iv: String, sha256: String) {
    self.path = path
    self.key = key
    self.iv = iv
    self.sha256 = sha256
  }
}
