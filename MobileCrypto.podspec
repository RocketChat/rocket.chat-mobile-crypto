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

  s.source_files = "ios/**/*.{h,m,mm,cpp,swift}"
  s.public_header_files = "ios/algorithms/AESCrypto.h", "ios/algorithms/RSACrypto.h", "ios/algorithms/CryptoUtils.h", "ios/algorithms/RandomUtils.h", "ios/algorithms/HMACCrypto.h", "ios/algorithms/PBKDF2Crypto.h", "ios/algorithms/SHACrypto.h", "ios/algorithms/FileUtils.h"
  s.private_header_files = "ios/MobileCrypto.h"
  s.swift_version = "5.0"
  s.requires_arc = true
  
  # Module config — exposes the Swift-generated ObjC compat header so that
  # AESCrypto.m can find "MobileCrypto-Swift.h" via double-quoted import.
  # OBJECT_FILE_DIR_normal/$(CURRENT_ARCH) is where swiftc writes the header
  # in static-lib (non-use_frameworks!) builds; add it to the search path.
  s.pod_target_xcconfig = {
    'DEFINES_MODULE' => 'YES',
    'SWIFT_OBJC_INTERFACE_HEADER_NAME' => 'MobileCrypto-Swift.h',
    'HEADER_SEARCH_PATHS' => '$(inherited) $(PODS_TARGET_SRCROOT)/ios/algorithms $(OBJECT_FILE_DIR_normal)/$(CURRENT_ARCH)'
  }
  
  # Ensure Swift files are properly compiled and linked
  s.frameworks = 'Foundation'

  install_modules_dependencies(s)
end
