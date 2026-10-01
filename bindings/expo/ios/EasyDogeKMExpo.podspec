require "json"

package = JSON.parse(File.read(File.join(__dir__, "..", "package.json")))

Pod::Spec.new do |s|
  s.name = "EasyDogeKMExpo"
  s.version = package["version"]
  s.summary = "Expo native module bridge for EasyDoge Dogecoin key management"
  s.description = "Rust-backed Dogecoin key-management SDK for Expo custom dev-client and EAS builds."
  s.license = { :type => "MIT" }
  s.homepage = "https://github.com/simonbetton/easydoge-km"
  s.author = "EasyDoge Maintainers"
  s.platforms = { :ios => "16.4" }
  s.swift_version = "5.9"
  s.source = { :git => "https://github.com/simonbetton/easydoge-km.git", :tag => s.version.to_s }
  s.static_framework = true
  # Top-level Swift files only: vendor/ belongs to the EasyDogeKM and
  # EasyDogeKMFFI pods.
  s.source_files = "*.swift"
  s.dependency "ExpoModulesCore"
  s.dependency "EasyDogeKM"
  s.pod_target_xcconfig = {
    "DEFINES_MODULE" => "YES",
    "SWIFT_COMPILATION_MODE" => "wholemodule"
  }
end
