require "json"

package = JSON.parse(File.read(File.join(__dir__, "package.json")))

Pod::Spec.new do |s|
  s.name         = "MobileCrypto"
  s.version      = package["version"]
  s.summary      = package["description"]
  s.homepage     = package["homepage"]
  s.license      = package["license"]
  s.authors      = package["author"]

  s.platforms    = { :ios => min_ios_version_supported }
  s.source       = { :git => "https://github.com/RocketChat/rocket.chat-mobile-crypto.git", :tag => "#{s.version}" }

  s.source_files = "ios/**/*.swift"
  s.exclude_files = "ios/core/**/*"
  s.frameworks = "Foundation"

  s.dependency "MobileCryptoCore"
  s.pod_target_xcconfig = {
    "SWIFT_PACKAGE_NAME" => "MobileCrypto",
  }

  load "nitrogen/generated/ios/MobileCrypto+autolinking.rb"
  add_nitrogen_files(s)

  install_modules_dependencies(s)
end
