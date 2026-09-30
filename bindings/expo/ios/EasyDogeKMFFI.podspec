require "json"

package = JSON.parse(File.read(File.join(__dir__, "..", "package.json")))

# Generated UniFFI Swift bindings plus the prebuilt Rust static library.
# The pod is named EasyDogeKMFFI so its product (libEasyDogeKMFFI.a) cannot
# collide with the Rust archive (libeasydoge_km_ffi.a); the Swift module keeps
# the name the facade imports.
Pod::Spec.new do |s|
  s.name = "EasyDogeKMFFI"
  s.module_name = "easydoge_km_ffi"
  s.version = package["version"]
  s.summary = "Generated UniFFI Swift bindings and the prebuilt Rust library for EasyDoge KM."
  s.description = "Generated UniFFI Swift bindings and the prebuilt easydoge-km-ffi static library, vendored into the @easydoge/km-expo npm package."
  s.license = { :type => "MIT" }
  s.homepage = "https://github.com/simonbetton/easydoge-km"
  s.author = "EasyDoge Maintainers"
  s.platforms = { :ios => "16.4" }
  s.swift_version = "5.9"
  s.source = { :git => "https://github.com/simonbetton/easydoge-km.git", :tag => s.version.to_s }
  s.static_framework = true
  s.source_files = "vendor/easydoge_km_ffi/**/*.swift"
  s.vendored_frameworks = "vendor/easydoge_km_ffi.xcframework"
  s.libraries = "iconv"
  s.pod_target_xcconfig = { "DEFINES_MODULE" => "YES" }
end
