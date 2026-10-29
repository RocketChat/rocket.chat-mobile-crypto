require "json"

package = JSON.parse(File.read(File.join(__dir__, "package.json")))

Pod::Spec.new do |s|
  s.name         = "MobileCryptoCore"
  s.version      = package["version"]
  s.summary      = package["description"]
  s.homepage     = package["homepage"]
  s.license      = package["license"]
  s.authors      = package["author"]

  s.platforms    = { :ios => "15.1" }
  s.source       = { :git => "https://github.com/RocketChat/rocket.chat-mobile-crypto.git", :tag => "#{s.version}" }

  s.swift_version = "5.9"
  s.source_files = "ios/core/**/*.swift"
  s.frameworks = "Foundation", "Security", "CryptoKit"

  s.pod_target_xcconfig = {
    "SWIFT_PACKAGE_NAME" => "MobileCrypto",
  }
end
