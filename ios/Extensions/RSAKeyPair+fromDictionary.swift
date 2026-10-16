import NitroModules

extension RSAKeyPair {
  static func from(dictionary: [AnyHashable: Any]) throws -> RSAKeyPair {
    guard let publicKey = dictionary["public"] as? String,
          let privateKey = dictionary["private"] as? String else {
      throw RuntimeError.error(withMessage: "Generated key pair is missing a key")
    }
    return RSAKeyPair(publicKey: publicKey, privateKey: privateKey)
  }
}
