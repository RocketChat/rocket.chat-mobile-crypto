package struct JWK: Decodable {
  package let kty: String
  package let alg: String?
  package let ext: Bool?
  package let keyOperations: [String]?
  package let n: String
  package let e: String
  package let d: String?
  package let p: String?
  package let q: String?
  package let dp: String?
  package let dq: String?
  package let qi: String?

  package init(
    kty: String,
    alg: String?,
    ext: Bool?,
    keyOperations: [String]?,
    n: String,
    e: String,
    d: String?,
    p: String?,
    q: String?,
    dp: String?,
    dq: String?,
    qi: String?
  ) {
    self.kty = kty
    self.alg = alg
    self.ext = ext
    self.keyOperations = keyOperations
    self.n = n
    self.e = e
    self.d = d
    self.p = p
    self.q = q
    self.dp = dp
    self.dq = dq
    self.qi = qi
  }

  private enum CodingKeys: String, CodingKey {
    case kty, alg, ext, n, e, d, p, q, dp, dq, qi
    case keyOperations = "key_ops"
  }
}
