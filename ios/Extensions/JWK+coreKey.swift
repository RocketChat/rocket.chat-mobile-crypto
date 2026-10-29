import MobileCryptoCore

extension JWK {
  init(_ coreKey: MobileCryptoCore.JWK) {
    self.init(
      kty: coreKey.kty,
      alg: coreKey.alg,
      ext: coreKey.ext,
      key_ops: coreKey.keyOperations,
      n: coreKey.n,
      e: coreKey.e,
      d: coreKey.d,
      p: coreKey.p,
      q: coreKey.q,
      dp: coreKey.dp,
      dq: coreKey.dq,
      qi: coreKey.qi
    )
  }

  var coreKey: MobileCryptoCore.JWK {
    MobileCryptoCore.JWK(
      kty: kty,
      alg: alg,
      ext: ext,
      keyOperations: key_ops,
      n: n,
      e: e,
      d: d,
      p: p,
      q: q,
      dp: dp,
      dq: dq,
      qi: qi
    )
  }
}
