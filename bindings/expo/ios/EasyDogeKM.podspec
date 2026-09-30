require "json"

package = JSON.parse(File.read(File.join(__dir__, "..", "package.json")))

# Handwritten Swift facade (SDK wrapper, WireCodec, Keychain storage adapter),
# vendored unchanged from bindings/swift/Sources/EasyDogeKM.
Pod::Spec.new do |s|
  s.name = "EasyDogeKM"
  s.version = package["version"]
  s.summary = "Swift facade for the EasyDoge Dogecoin key-management SDK."
  s.description = "Handwritten Swift facade and Keychain storage adapter over the UniFFI bindings, vendored into the @easydoge/km-expo npm package."
  s.license = { :type => "MIT" }
  s.homepage = "https://github.com/simonbetton/easydoge-km"
  s.author = "EasyDoge Maintainers"
  s.platforms = { :ios => "16.4" }
  s.swift_version = "5.9"
  s.source = { :git => "https://github.com/simonbetton/easydoge-km.git", :tag => s.version.to_s }
  s.static_framework = true
  s.source_files = "vendor/EasyDogeKM/**/*.swift"
  s.dependency "EasyDogeKMFFI"
  s.pod_target_xcconfig = { "DEFINES_MODULE" => "YES" }
end
