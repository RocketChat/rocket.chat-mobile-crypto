import MobileCryptoCore

extension RSAKeyPair {
  init(_ coreKeyPair: MobileCryptoCore.RSAKeyPair) {
    self.init(publicKey: coreKeyPair.publicKey, privateKey: coreKeyPair.privateKey)
  }
}
