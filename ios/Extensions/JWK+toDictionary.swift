extension JWK {
  func toDictionary() -> [String: Any] {
    var dictionary: [String: Any] = ["kty": kty, "n": n, "e": e]
    dictionary["alg"] = alg
    dictionary["ext"] = ext
    dictionary["key_ops"] = key_ops
    dictionary["d"] = d
    dictionary["p"] = p
    dictionary["q"] = q
    dictionary["dp"] = dp
    dictionary["dq"] = dq
    dictionary["qi"] = qi
    return dictionary
  }
}
