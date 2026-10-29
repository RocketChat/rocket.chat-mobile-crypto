import Foundation

extension String {
  var normalizedFilePath: String {
    let fileScheme = "file://"
    guard hasPrefix(fileScheme) else { return self }
    let path = String(dropFirst(fileScheme.count))
    return path.removingPercentEncoding ?? path
  }
}
