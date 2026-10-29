extension JWK {
  package var json: String {
    let stringMembers: [(String, String?)] = [
      ("n", n), ("e", e), ("d", d), ("p", p), ("q", q), ("dp", dp), ("dq", dq), ("qi", qi),
    ]
    var members = [member("kty", quoted(kty))]
    alg.map { members.append(member("alg", quoted($0))) }
    ext.map { members.append(member("ext", $0 ? "true" : "false")) }
    keyOperations.map { members.append(member("key_ops", "[\($0.map(quoted).joined(separator: ","))]")) }
    for (name, value) in stringMembers {
      value.map { members.append(member(name, quoted($0))) }
    }
    return "{\(members.joined(separator: ","))}"
  }

  private func member(_ name: String, _ value: String) -> String {
    "\(quoted(name)):\(value)"
  }

  private func quoted(_ value: String) -> String {
    let escaped = value
      .replacingOccurrences(of: "\\", with: "\\\\")
      .replacingOccurrences(of: "\"", with: "\\\"")
    return "\"\(escaped)\""
  }
}
