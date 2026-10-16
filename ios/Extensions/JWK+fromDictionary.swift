import NitroModules

extension JWK {
  static func from(dictionary: [AnyHashable: Any]) throws -> JWK {
    guard let kty = dictionary["kty"] as? String,
          let n = dictionary["n"] as? String,
          let e = dictionary["e"] as? String else {
      throw RuntimeError.error(withMessage: "Exported key is missing kty, n or e")
    }
    return JWK(
      kty: kty,
      alg: dictionary["alg"] as? String,
      ext: dictionary["ext"] as? Bool,
      key_ops: dictionary["key_ops"] as? [String],
      n: n,
      e: e,
      d: dictionary["d"] as? String,
      p: dictionary["p"] as? String,
      q: dictionary["q"] as? String,
      dp: dictionary["dp"] as? String,
      dq: dictionary["dq"] as? String,
      qi: dictionary["qi"] as? String
    )
  }
}
