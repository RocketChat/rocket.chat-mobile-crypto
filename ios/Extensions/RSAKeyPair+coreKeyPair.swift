import MobileCryptoCore

extension RSAKeyPair {
  init(_ coreKeyPair: MobileCryptoCore.RSAKeyPair) {
    self.init(
      publicKey: HybridRSAPublicKey(key: coreKeyPair.publicKey),
      privateKey: HybridRSAPrivateKey(key: coreKeyPair.privateKey)
    )
  }
}
