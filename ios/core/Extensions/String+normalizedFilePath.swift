import Foundation

private let fileScheme = "file://"

extension String {
  var normalizedFilePath: String {
    guard hasPrefix(fileScheme) else { return self }
    let path = String(dropFirst(fileScheme.count))
    return path.removingPercentEncoding ?? path
  }

  var fileURIString: String {
    fileScheme + self
  }
}
